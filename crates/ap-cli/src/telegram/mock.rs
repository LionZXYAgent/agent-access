//! In-process mock of the Telegram Bot API for tests.
//!
//! Implements `getMe`, `getUpdates`, `sendMessage`, `editMessageText` and
//! `answerCallbackQuery`, records every call, and lets tests inject button
//! presses and chat messages as updates.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::routing::post;
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify};

pub const TOKEN: &str = "123456:TEST-TOKEN-abcdefghijklmnopqrstuvwxyz";

#[derive(Debug, Clone)]
pub struct Sent {
    pub message_id: i64,
    pub chat_id: i64,
    pub text: String,
    pub buttons: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Edit {
    pub message_id: i64,
    pub text: String,
    pub buttons: Vec<String>,
}

#[derive(Default)]
struct MockState {
    next_message_id: i64,
    next_update_id: i64,
    sent: Vec<Sent>,
    edits: Vec<Edit>,
    answers: Vec<String>,
    updates: VecDeque<Value>,
}

#[derive(Clone)]
pub struct MockTelegram {
    state: Arc<Mutex<MockState>>,
    notify: Arc<Notify>,
    pub url: String,
}

fn callback_data(markup: Option<&Value>) -> Vec<String> {
    markup
        .and_then(|m| m["inline_keyboard"].as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r.as_array())
                .flatten()
                .filter_map(|b| b["callback_data"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn handle(
    State(mock): State<MockTelegram>,
    Path((bot, method)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Json<Value> {
    if bot != format!("bot{TOKEN}") {
        return Json(json!({"ok": false, "error_code": 401, "description": "Unauthorized"}));
    }
    match method.as_str() {
        "getMe" => Json(
            json!({"ok": true, "result": {"id": 42, "is_bot": true, "username": "aac_test_bot"}}),
        ),
        "sendMessage" => {
            let mut st = mock.state.lock().await;
            st.next_message_id += 1;
            let sent = Sent {
                message_id: st.next_message_id,
                chat_id: body["chat_id"].as_i64().unwrap_or_default(),
                text: body["text"].as_str().unwrap_or_default().to_string(),
                buttons: callback_data(body.get("reply_markup")),
            };
            let result = json!({"message_id": sent.message_id, "chat": {"id": sent.chat_id}});
            st.sent.push(sent);
            Json(json!({"ok": true, "result": result}))
        }
        "editMessageText" => {
            let mut st = mock.state.lock().await;
            let edit = Edit {
                message_id: body["message_id"].as_i64().unwrap_or_default(),
                text: body["text"].as_str().unwrap_or_default().to_string(),
                buttons: callback_data(body.get("reply_markup")),
            };
            let result = json!({"message_id": edit.message_id, "chat": {"id": body["chat_id"]}});
            st.edits.push(edit);
            Json(json!({"ok": true, "result": result}))
        }
        "answerCallbackQuery" => {
            let mut st = mock.state.lock().await;
            st.answers
                .push(body["text"].as_str().unwrap_or_default().to_string());
            Json(json!({"ok": true, "result": true}))
        }
        "getUpdates" => {
            let offset = body["offset"].as_i64().unwrap_or(0);
            // Short long-poll so tests stay fast.
            for _ in 0..2 {
                {
                    let mut st = mock.state.lock().await;
                    st.updates
                        .retain(|u| u["update_id"].as_i64().unwrap_or_default() >= offset);
                    if !st.updates.is_empty() {
                        let ups: Vec<Value> = st.updates.iter().cloned().collect();
                        return Json(json!({"ok": true, "result": ups}));
                    }
                }
                let _ =
                    tokio::time::timeout(Duration::from_millis(200), mock.notify.notified()).await;
            }
            Json(json!({"ok": true, "result": []}))
        }
        _ => Json(json!({"ok": false, "error_code": 404, "description": "Not Found"})),
    }
}

impl MockTelegram {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock telegram");
        let addr: SocketAddr = listener.local_addr().expect("local addr");
        let mock = Self {
            state: Arc::new(Mutex::new(MockState::default())),
            notify: Arc::new(Notify::new()),
            url: format!("http://{addr}"),
        };
        let app = axum::Router::new()
            .route("/{bot}/{method}", post(handle))
            .with_state(mock.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        mock
    }

    async fn push_update(&self, mut update: Value) {
        let mut st = self.state.lock().await;
        st.next_update_id += 1;
        update["update_id"] = json!(st.next_update_id);
        st.updates.push_back(update);
        drop(st);
        self.notify.notify_waiters();
    }

    /// Simulate a button press.
    pub async fn press(&self, from_id: i64, chat_id: i64, message_id: i64, data: &str) {
        let id = format!("cb-{}", rand::random::<u32>());
        self.push_update(json!({
            "callback_query": {
                "id": id,
                "from": {"id": from_id, "is_bot": false, "first_name": "T"},
                "message": {"message_id": message_id, "chat": {"id": chat_id, "type": "private"}},
                "data": data
            }
        }))
        .await;
    }

    /// Simulate a text message (bot command).
    pub async fn say(&self, from_id: i64, chat_id: i64, text: &str) {
        self.push_update(json!({
            "message": {
                "message_id": 9000,
                "from": {"id": from_id, "is_bot": false, "first_name": "T"},
                "chat": {"id": chat_id, "type": "private"},
                "text": text
            }
        }))
        .await;
    }

    pub async fn sent(&self) -> Vec<Sent> {
        self.state.lock().await.sent.clone()
    }

    pub async fn edits(&self) -> Vec<Edit> {
        self.state.lock().await.edits.clone()
    }

    pub async fn answers(&self) -> Vec<String> {
        self.state.lock().await.answers.clone()
    }

    /// Wait until `pred` holds over the recorded state (or panic after 5s).
    pub async fn wait_for<F>(&self, what: &str, pred: F)
    where
        F: Fn(&[Sent], &[Edit], &[String]) -> bool,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            {
                let st = self.state.lock().await;
                if pred(&st.sent, &st.edits, &st.answers) {
                    return;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
