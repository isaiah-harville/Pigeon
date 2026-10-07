#[test]
fn flush_queue_replays_everything_stored() {
    let st = state(3600, 100);
    let (ptx, _prx) = channel();
    publish(&st, &ptx, addr(1), "b25l".into());
    publish(&st, &ptx, addr(1), "dHdv".into());
    let (ftx, mut frx) = channel();
    flush_queue(&st, &addr(1), &ftx);
    let mut count = 0;
    while let Ok(ServerMsg::Envelope { .. }) = frx.try_recv() {
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn ack_deletes_only_the_named_envelope() {
    let st = state(3600, 100);
    let (ptx, mut prx) = channel();
    publish(&st, &ptx, addr(1), "b25l".into());
    publish(&st, &ptx, addr(1), "dHdv".into());
    let id = match prx.try_recv().unwrap() {
        ServerMsg::Published { id, .. } => id,
        _ => panic!("expected a Published reply"),
    };
    ack(&st, &addr(1), &id);
    assert_eq!(queue_len(&st, &addr(1)), 1);
    ack(&st, &addr(1), "deadbeef"); // unknown id is a no-op
    assert_eq!(queue_len(&st, &addr(1)), 1);
}

#[test]
fn max_queue_drops_oldest() {
    let st = state(3600, 2);
    let (tx, _rx) = channel();
    for i in 0..5 {
        publish(&st, &tx, addr(1), format!("e{i}"));
    }
    assert_eq!(queue_len(&st, &addr(1)), 2);
}

#[test]
fn expire_drops_old_envelopes_and_reclaims_empty_mailboxes() {
    let st = state(3600, 100);
    let (tx, _rx) = channel();
    publish(&st, &tx, addr(1), "b25l".into());
    // A cutoff just past the deposit's timestamp retires it.
    expire_mailboxes(&st, crate::clock::now() + 1);
    assert_eq!(mailbox_count(&st), 0);
    assert_eq!(total_bytes(&st), 0);
}

#[test]
fn verify_ownership_accepts_valid_and_rejects_forgery() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let mailbox = hex::encode(sk.verifying_key().to_bytes());
    let nonce = [9u8; 32];
    let sig_b64 = B64.encode(sk.sign(&nonce).to_bytes());

    assert!(verify_ownership(&mailbox, &nonce, &sig_b64));
    assert!(!verify_ownership(&mailbox, &[0u8; 32], &sig_b64)); // wrong nonce
    let other = hex::encode(
        SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    assert!(!verify_ownership(&other, &nonce, &sig_b64)); // wrong key
    assert!(!verify_ownership(&mailbox, &nonce, "not base64!!")); // malformed sig
    assert!(!verify_ownership("xyz", &nonce, &sig_b64)); // malformed address
}

#[test]
fn publish_prunes_dead_subscribers() {
    let st = state(3600, 100);
    let (ptx, _prx) = channel();
    let (stx, srx) = channel();
    register_subscriber(&st, &addr(1), 1, stx);
    drop(srx); // receiver gone -> live send fails
    publish(&st, &ptx, addr(1), "b25l".into());
    assert_eq!(subscriber_count(&st, &addr(1)), 0);
}

#[test]
fn register_push_requires_authentication() {
    // No authenticated mailbox: a token must never be bound (the auth gate fires
    // before anything else), so only the mailbox owner can ever attach a token.
    let st = state(3600, 100);
    let (tx, mut rx) = channel();
    register_push(&st, &tx, None, "aabbccdd".into());
    assert!(matches!(rx.try_recv().unwrap(), ServerMsg::Error { .. }));
}

#[test]
fn register_push_rejected_when_no_gateway() {
    // A relay with no APNs gateway (every self-hosted / third-party relay)
    // refuses registration outright rather than hoarding tokens it can't use.
    let st = state(3600, 100);
    let (tx, mut rx) = channel();
    register_push(&st, &tx, Some(&addr(1)), "aabbccdd".into());
    match rx.try_recv().unwrap() {
        ServerMsg::Error { message, .. } => assert_eq!(message, "push not supported"),
        other => panic!("expected an Error reply, got {other:?}"),
    }
}

#[test]
fn invite_mailbox_cannot_register_a_device_token() {
    let st = state(3600, 100);
    let (tx, mut rx) = channel();
    mailbox_register_push(&st.push, &tx, Some(&addr(1)), true, "aabbccdd".into());
    match rx.try_recv().unwrap() {
        ServerMsg::Error { message, .. } => assert_eq!(message, "invite push not supported"),
        other => panic!("expected an Error reply, got {other:?}"),
    }
}

#[test]
fn pairwise_mailbox_limits_concurrent_backlog_readers() {
    let st = state(3600, 100);
    let address = addr(1);
    let (first, _first_rx) = channel();
    let (second, _second_rx) = channel();
    let (third, _third_rx) = channel();
    assert!(mailbox_register_subscriber(&st.mailbox, &address, 1, first));
    assert!(mailbox_register_subscriber(
        &st.mailbox,
        &address,
        2,
        second
    ));
    assert!(!mailbox_register_subscriber(
        &st.mailbox,
        &address,
        3,
        third.clone()
    ));
    mailbox_remove_subscriber(&st.mailbox, &address, 1);
    assert!(mailbox_register_subscriber(&st.mailbox, &address, 3, third));
}

#[test]
fn remove_subscriber_removes_by_conn_id() {
    let st = state(3600, 100);
    let (s1, _r1) = channel();
    let (s2, _r2) = channel();
    register_subscriber(&st, &addr(1), 1, s1);
    register_subscriber(&st, &addr(1), 2, s2);
    remove_subscriber(&st, &addr(1), 1);
    assert_eq!(subscriber_count(&st, &addr(1)), 1);
}

#[test]
fn switching_mailbox_drops_the_previous_subscription() {
    let st = state(3600, 100);
    let (tx, _rx) = channel();
    switch_subscription(&st, None, &addr(1), 7, tx.clone());
    switch_subscription(&st, Some(&addr(1)), &addr(2), 7, tx);
    assert_eq!(subscriber_count(&st, &addr(1)), 0);
    assert_eq!(subscriber_count(&st, &addr(2)), 1);
}

#[test]
fn re_authenticating_the_same_mailbox_keeps_one_subscription() {
    let st = state(3600, 100);
    let (tx, _rx) = channel();
    switch_subscription(&st, None, &addr(1), 7, tx.clone());
    switch_subscription(&st, Some(&addr(1)), &addr(1), 7, tx);
    assert_eq!(subscriber_count(&st, &addr(1)), 1);
}

#[test]
fn deposits_to_a_new_mailbox_are_refused_at_the_mailbox_cap() {
    let st = bounded_state(3600, 100, 2, usize::MAX);
    let (tx, mut rx) = channel();
    publish(&st, &tx, addr(1), "b25l".into());
    publish(&st, &tx, addr(2), "b25l".into());
    while rx.try_recv().is_ok() {} // drain the two `published` replies

    publish(&st, &tx, addr(3), "b25l".into());
    assert!(matches!(rx.try_recv().unwrap(), ServerMsg::Error { .. }));
    assert_eq!(mailbox_count(&st), 2);
    assert_eq!(queue_len(&st, &addr(3)), 0);

    // An existing mailbox still accepts deposits at the cap.
    publish(&st, &tx, addr(1), "dHdv".into());
    assert_eq!(queue_len(&st, &addr(1)), 2);
}

#[test]
fn the_global_byte_ceiling_evicts_from_the_largest_mailbox() {
    // Room for ~10 four-byte envelopes across the whole relay.
    let st = bounded_state(3600, 100, 100, 40);
    let (tx, _rx) = channel();

    publish(&st, &tx, addr(1), "b25l".into()); // one quiet mailbox
    for _ in 0..20 {
        publish(&st, &tx, addr(2), "Zmxvb2Q=".into()); // one flooding mailbox
    }

    assert!(total_bytes(&st) <= 40);
    // The flooder paid for its own pressure; the quiet mailbox kept its mail.
    assert_eq!(queue_len(&st, &addr(1)), 1);
    assert!(queue_len(&st, &addr(2)) < 20);
}

#[test]
fn byte_accounting_tracks_deposits_acks_and_expiry() {
    let st = state(3600, 100);
    let (tx, _rx) = channel();
    publish(&st, &tx, addr(1), "b25l".into()); // 4 bytes
    publish(&st, &tx, addr(1), "dHdvdHdv".into()); // 8 bytes
    assert_eq!(total_bytes(&st), 12);

    let first = state_first_id(&st, &addr(1));
    ack(&st, &addr(1), &first);
    assert_eq!(total_bytes(&st), 8);

    expire_mailboxes(&st, crate::clock::now() + 1);
    assert_eq!(total_bytes(&st), 0);
}

#[test]
fn a_backed_up_subscriber_is_kept_but_never_buffered_past_the_bound() {
    let st = state(3600, usize::MAX);
    let (publisher, _pub_rx) = channel();
    let (sub, mut sub_rx) = channel();
    register_subscriber(&st, &addr(1), 1, sub);

    // Never drain `sub_rx` during the burst: the channel fills, and the relay
    // stops buffering rather than growing without limit.
    let burst = SUBSCRIBER_CHANNEL_CAPACITY + 10;
    for _ in 0..burst {
        publish(&st, &publisher, addr(1), "b25l".into());
    }

    // The subscription survives — a healthy socket that fell behind must keep
    // receiving once it catches up, and the skipped envelopes are still queued.
    assert_eq!(subscriber_count(&st, &addr(1)), 1);
    assert_eq!(queue_len(&st, &addr(1)), burst);

    let mut buffered = 0;
    while sub_rx.try_recv().is_ok() {
        buffered += 1;
    }
    assert_eq!(buffered, SUBSCRIBER_CHANNEL_CAPACITY);

    // Caught up: live delivery resumes.
    publish(&st, &publisher, addr(1), "bmV3".into());
    assert!(matches!(
        sub_rx.try_recv().unwrap(),
        ServerMsg::Envelope { .. }
    ));
}

#[test]
fn a_disconnected_subscriber_is_dropped() {
    let st = state(3600, usize::MAX);
    let (publisher, _pub_rx) = channel();
    let (sub, sub_rx) = channel();
    register_subscriber(&st, &addr(1), 1, sub);
    drop(sub_rx); // the connection went away

    publish(&st, &publisher, addr(1), "b25l".into());
    assert_eq!(subscriber_count(&st, &addr(1)), 0);
}

/// The id of the oldest envelope in a mailbox.
fn state_first_id(state: &TestState, mailbox: &str) -> String {
    state
        .mailbox
        .store
        .lock()
        .unwrap()
        .get(mailbox)
        .unwrap()
        .queue[0]
        .id
        .clone()
}
