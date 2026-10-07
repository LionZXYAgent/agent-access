//! Telegram approval tests against an in-process mock Bot API.

use std::time::Duration;

use ap_client::{CredentialData, CredentialQuery, IdentityFingerprint};
use secrecy::SecretString;
use secrecy::zeroize::Zeroizing;

use super::approver::{Decision, TelegramApprover, TelegramSettings};
use super::grants::GrantDuration;
use super::message::{ApprovalPrompt, DeviceLabel};
use super::mock::{MockTelegram, TOKEN};
use super::{BotApi, CredentialGate};

const OWNER: i64 = 1001;
const STRANGER: i64 = 2002;
const SECRET: &str = "hunter2-SUPER-SECRET";

async fn setup(timeout: Duration) -> (MockTelegram, TelegramApprover) {
    let mock = MockTelegram::start().await;
    let api = BotApi::new(&mock.url, SecretString::from(TOKEN.to_string())).expect("api");
    let (approver, _poller) = TelegramApprover::start(
        api,
        TelegramSettings {
            owner_id: OWNER,
            chat_id: OWNER,
            timeout,
        },
    )
    .await
    .expect("approver should start");
    (mock, approver)
}

fn credential(id: &str) -> CredentialData {
    CredentialData {
        username: Some("alice".into()),
        password: Some(Zeroizing::new(SECRET.to_string())),
        totp: Some("JBSWY3DPEHPK3PXP".into()),
        uri: Some("https://github.com".into()),
        notes: None,
        credential_id: Some(id.into()),
        domain: Some("github.com".into()),
    }
}

fn device(byte: u8) -> DeviceLabel {
    DeviceLabel {
        name: Some(format!("agent-{byte}")),
        identity: IdentityFingerprint([byte; 32]),
    }
}

fn github() -> CredentialQuery {
    CredentialQuery::Domain("github.com".into())
}

/// Send a credential prompt via gate_credential, expecting a prompt (not a grant).
async fn prompt(approver: &TelegramApprover, dev: u8, item: &str) -> super::PendingApproval {
    match approver
        .gate_credential(
            device(dev),
            &github(),
            &credential(item),
            "req-1",
            1_791_400_000,
        )
        .await
        .expect("gate should succeed")
    {
        CredentialGate::Pending(p) => p,
        CredentialGate::AutoApproved(_) => panic!("unexpected auto-approval"),
    }
}

fn button_for(buttons: &[String], action: &str) -> String {
    buttons
        .iter()
        .find(|b| b.ends_with(&format!(":{action}")))
        .unwrap_or_else(|| panic!("no {action} button in {buttons:?}"))
        .clone()
}

async fn decision(p: super::PendingApproval) -> Decision {
    tokio::time::timeout(Duration::from_secs(5), p.decision)
        .await
        .expect("decision should arrive")
        .expect("sender should not be dropped")
}

#[tokio::test]
async fn start_fails_with_invalid_token() {
    let mock = MockTelegram::start().await;
    let api = BotApi::new(&mock.url, SecretString::from("999:WRONG".to_string())).expect("api");
    let err = TelegramApprover::start(
        api,
        TelegramSettings {
            owner_id: OWNER,
            chat_id: OWNER,
            timeout: Duration::from_secs(5),
        },
    )
    .await
    .err()
    .expect("should fail");
    assert!(err.to_string().contains("Unauthorized"));
    assert!(!err.to_string().contains("WRONG"));
}

#[tokio::test]
async fn prompt_has_buttons_details_and_no_secrets() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let _p = prompt(&approver, 1, "item-1").await;
    let sent = mock.sent().await;
    assert_eq!(sent.len(), 1);
    let msg = &sent[0];
    assert_eq!(msg.chat_id, OWNER);
    assert_eq!(msg.buttons.len(), 5, "allow, decline, 15m, 1h, forever");
    for action in ["a", "d", "m15", "h1", "f"] {
        button_for(&msg.buttons, action);
    }
    // All buttons share one unguessable id.
    let ids: std::collections::HashSet<_> = msg
        .buttons
        .iter()
        .map(|b| b.split(':').nth(1).map(str::to_string))
        .collect();
    assert_eq!(ids.len(), 1);
    assert!(msg.text.contains("agent-1"));
    assert!(msg.text.contains("domain \"github.com\""));
    assert!(msg.text.contains("Request ID: req-1"));
    assert!(
        msg.text
            .contains("Fields to release: username, password, totp, uri")
    );
    assert!(!msg.text.contains(SECRET));
    assert!(!msg.text.contains("JBSWY3DPEHPK3PXP"));
}

#[tokio::test]
async fn owner_allow_once() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let p = prompt(&approver, 1, "item-1").await;
    let msg = mock.sent().await.remove(0);
    mock.press(OWNER, OWNER, msg.message_id, &button_for(&msg.buttons, "a"))
        .await;
    assert_eq!(decision(p).await, Decision::Allow);
    mock.wait_for("edit", |_, e, _| !e.is_empty()).await;
    let edit = mock.edits().await.remove(0);
    assert_eq!(edit.message_id, msg.message_id);
    assert!(edit.text.contains("ALLOWED once via Telegram"));
    assert!(edit.buttons.is_empty(), "buttons removed after decision");
    assert!(mock.answers().await.contains(&"Allowed".to_string()));
    // One-time allow creates no grant.
    assert!(approver.list_grants().await.is_empty());
}

#[tokio::test]
async fn owner_decline() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let p = prompt(&approver, 1, "item-1").await;
    let msg = mock.sent().await.remove(0);
    mock.press(OWNER, OWNER, msg.message_id, &button_for(&msg.buttons, "d"))
        .await;
    assert_eq!(decision(p).await, Decision::Decline);
    mock.wait_for("edit", |_, e, _| !e.is_empty()).await;
    assert!(mock.edits().await[0].text.contains("DECLINED via Telegram"));
}

#[tokio::test]
async fn wrong_user_and_wrong_chat_are_rejected() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let mut p = prompt(&approver, 1, "item-1").await;
    let msg = mock.sent().await.remove(0);
    let allow = button_for(&msg.buttons, "a");

    mock.press(STRANGER, OWNER, msg.message_id, &allow).await;
    // Owner's id but pressed in a different chat (e.g. message forwarded to a group).
    mock.press(OWNER, 555, msg.message_id, &allow).await;
    mock.wait_for("two rejections", |_, _, a| {
        a.iter().filter(|x| *x == "Not authorized").count() == 2
    })
    .await;
    assert!(
        p.decision.try_recv().is_err(),
        "request must still be pending"
    );
    assert!(mock.edits().await.is_empty());

    // The real owner can still answer afterwards.
    mock.press(OWNER, OWNER, msg.message_id, &button_for(&msg.buttons, "d"))
        .await;
    assert_eq!(decision(p).await, Decision::Decline);
}

#[tokio::test]
async fn timeout_auto_declines_and_late_press_is_expired() {
    let (mock, approver) = setup(Duration::from_millis(400)).await;
    let p = prompt(&approver, 1, "item-1").await;
    assert_eq!(decision(p).await, Decision::TimedOut);
    assert!(!Decision::TimedOut.is_allowed());
    mock.wait_for("timeout edit", |_, e, _| !e.is_empty()).await;
    assert!(mock.edits().await[0].text.contains("TIMED OUT"));

    let msg = mock.sent().await.remove(0);
    mock.press(OWNER, OWNER, msg.message_id, &button_for(&msg.buttons, "a"))
        .await;
    mock.wait_for("expired answer", |_, _, a| {
        a.iter().any(|x| x.contains("expired"))
    })
    .await;
    assert_eq!(mock.edits().await.len(), 1, "no second edit");
}

#[tokio::test]
async fn callbacks_are_single_use() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let p = prompt(&approver, 1, "item-1").await;
    let msg = mock.sent().await.remove(0);
    let allow = button_for(&msg.buttons, "a");
    mock.press(OWNER, OWNER, msg.message_id, &allow).await;
    assert_eq!(decision(p).await, Decision::Allow);
    // Replay the same callback, and also try the decline button afterwards.
    mock.press(OWNER, OWNER, msg.message_id, &allow).await;
    mock.press(OWNER, OWNER, msg.message_id, &button_for(&msg.buttons, "d"))
        .await;
    mock.wait_for("two expired answers", |_, _, a| {
        a.iter().filter(|x| x.contains("expired")).count() == 2
    })
    .await;
    assert_eq!(mock.edits().await.len(), 1);
}

#[tokio::test]
async fn forged_callback_id_is_ignored() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let mut p = prompt(&approver, 1, "item-1").await;
    let msg = mock.sent().await.remove(0);
    mock.press(
        OWNER,
        OWNER,
        msg.message_id,
        "aac:00000000000000000000000000000000:a",
    )
    .await;
    mock.press(OWNER, OWNER, msg.message_id, "garbage").await;
    mock.wait_for("answers", |_, _, a| a.len() == 2).await;
    assert!(p.decision.try_recv().is_err(), "still pending");
}

#[tokio::test]
async fn resolved_locally_updates_message_and_blocks_presses() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let p = prompt(&approver, 1, "item-1").await;
    approver
        .resolve_externally(&p.id, super::message::Outcome::AllowedLocally)
        .await;
    assert!(mock.edits().await[0].text.contains("ALLOWED locally"));
    let msg = mock.sent().await.remove(0);
    mock.press(OWNER, OWNER, msg.message_id, &button_for(&msg.buttons, "d"))
        .await;
    mock.wait_for("expired", |_, _, a| a.iter().any(|x| x.contains("expired")))
        .await;
}

#[tokio::test]
async fn timed_grant_auto_approves_matching_requests_only() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let p = prompt(&approver, 1, "item-1").await;
    let msg = mock.sent().await.remove(0);
    mock.press(
        OWNER,
        OWNER,
        msg.message_id,
        &button_for(&msg.buttons, "m15"),
    )
    .await;
    assert_eq!(
        decision(p).await,
        Decision::AllowFor(GrantDuration::Minutes15)
    );
    mock.wait_for("grant edit", |_, e, _| !e.is_empty()).await;
    let edit = mock.edits().await.remove(0);
    assert!(edit.text.contains("grant for 15 minutes"));
    assert_eq!(
        edit.buttons.len(),
        1,
        "edited message offers a revoke button"
    );
    assert!(edit.buttons[0].ends_with(":r"));
    let grants = approver.list_grants().await;
    assert_eq!(grants.len(), 1);
    assert!(grants[0].expires_epoch.is_some());

    // Same device + query + item → auto-approved, and NO Telegram message is sent.
    let sent_before = mock.sent().await.len();
    let gate = approver
        .gate_credential(device(1), &github(), &credential("item-1"), "req-2", 0)
        .await
        .expect("gate");
    assert!(matches!(gate, CredentialGate::AutoApproved(_)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        mock.sent().await.len(),
        sent_before,
        "auto-approval must not message Telegram"
    );

    // Different device → prompt.
    let _ = prompt(&approver, 2, "item-1").await;
    // Same device, query resolves to a different item → prompt.
    let _ = prompt(&approver, 1, "item-2").await;
    // Same device + item but different query → prompt.
    let other = approver
        .gate_credential(
            device(1),
            &CredentialQuery::Id("item-1".into()),
            &credential("item-1"),
            "req-3",
            0,
        )
        .await
        .expect("gate");
    assert!(matches!(other, CredentialGate::Pending(_)));
}

#[tokio::test]
async fn forever_grant_holds_until_revoked_via_command() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let p = prompt(&approver, 1, "item-1").await;
    let msg = mock.sent().await.remove(0);
    mock.press(OWNER, OWNER, msg.message_id, &button_for(&msg.buttons, "f"))
        .await;
    assert_eq!(
        decision(p).await,
        Decision::AllowFor(GrantDuration::Forever)
    );
    mock.wait_for("edit", |_, e, _| !e.is_empty()).await;
    assert!(mock.edits().await[0].text.contains("until revoked"));
    let grants = approver.list_grants().await;
    assert!(grants[0].expires_at.is_none());

    for i in 0..3 {
        let gate = approver
            .gate_credential(
                device(1),
                &github(),
                &credential("item-1"),
                &format!("r{i}"),
                0,
            )
            .await
            .expect("gate");
        assert!(matches!(gate, CredentialGate::AutoApproved(_)));
    }

    // Non-owner commands are ignored.
    mock.say(STRANGER, STRANGER, "/revoke all").await;
    // /grants lists it with a revoke button.
    mock.say(OWNER, OWNER, "/grants").await;
    mock.wait_for("grant list", |s, _, _| {
        s.iter().any(|m| m.text.starts_with("Active grants"))
    })
    .await;
    let list = mock
        .sent()
        .await
        .into_iter()
        .find(|m| m.text.starts_with("Active grants"))
        .expect("list");
    assert!(list.text.contains("#1 agent-1"));
    assert!(list.text.contains("until revoked"));
    assert_eq!(list.buttons.len(), 1);
    assert_eq!(
        approver.list_grants().await.len(),
        1,
        "stranger could not revoke"
    );

    mock.say(OWNER, OWNER, "/revoke all").await;
    mock.wait_for("revoke reply", |s, _, _| {
        s.iter().any(|m| m.text.contains("Revoked 1 grant"))
    })
    .await;
    assert!(approver.list_grants().await.is_empty());
    let _ = prompt(&approver, 1, "item-1").await; // asks again
}

#[tokio::test]
async fn revoke_by_button_and_by_number() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    // Two grants: device 1 (1h) and device 2 (forever).
    for (dev, action) in [(1u8, "h1"), (2u8, "f")] {
        let p = prompt(&approver, dev, "item-1").await;
        let msg = mock.sent().await.pop().expect("prompt");
        mock.press(
            OWNER,
            OWNER,
            msg.message_id,
            &button_for(&msg.buttons, action),
        )
        .await;
        assert!(decision(p).await.is_allowed());
    }
    mock.wait_for("two edits", |_, e, _| e.len() == 2).await;
    assert_eq!(approver.list_grants().await.len(), 2);

    // Revoke device 1's grant via the button on its edited message.
    let edit = mock.edits().await.remove(0);
    mock.press(OWNER, OWNER, edit.message_id, &edit.buttons[0])
        .await;
    mock.wait_for("revoke answer", |_, _, a| {
        a.iter().any(|x| x == "Grant revoked")
    })
    .await;
    let left = approver.list_grants().await;
    assert_eq!(left.len(), 1);
    assert!(left[0].label.contains("agent-2"));
    // Pressing the same revoke button again is harmless.
    mock.press(OWNER, OWNER, edit.message_id, &edit.buttons[0])
        .await;
    mock.wait_for("already revoked", |_, _, a| {
        a.iter().any(|x| x.contains("already expired or revoked"))
    })
    .await;

    // Revoke the remaining one by number.
    mock.say(OWNER, OWNER, "/revoke 1").await;
    mock.wait_for("revoked reply", |s, _, _| {
        s.iter().any(|m| m.text.contains("Grant revoked: agent-2"))
    })
    .await;
    assert!(approver.list_grants().await.is_empty());
}

#[tokio::test]
async fn pairing_prompt_offers_only_allow_decline() {
    let (mock, approver) = setup(Duration::from_secs(30)).await;
    let p = approver
        .request(
            &ApprovalPrompt::Pairing {
                device: device(9),
                handshake_fingerprint: "a1b2c3".into(),
            },
            None,
        )
        .await
        .expect("request");
    let msg = mock.sent().await.remove(0);
    assert_eq!(msg.buttons.len(), 2);
    assert!(msg.text.contains("a1b2c3"));
    mock.press(OWNER, OWNER, msg.message_id, &button_for(&msg.buttons, "a"))
        .await;
    assert_eq!(decision(p).await, Decision::Allow);
    assert!(approver.list_grants().await.is_empty());
}
