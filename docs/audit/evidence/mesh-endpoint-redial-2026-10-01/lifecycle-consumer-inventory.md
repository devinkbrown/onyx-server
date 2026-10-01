# Mesh lifecycle consumer inventory

Frozen server SHA-256: `0323be5cfb568173b41fb8fc343356947cb62f83ef74e4c2efc6c4e403b8aa49`.

This inventory supersedes the earlier 95/210-method scans. It unions actual S2S fields/flags, establishment and raw/active identity APIs, per-link send/take operations, roster readers, published identity cache, every direct shared-policy method, and the parent's additional consumer list. Nested comments can overmatch; those functions are explicitly classified. The function count is an index, not evidence of correctness by itself. Source and raw extracted bodies are retained in cache.

## Shared contract

`ConnState.meshAdmissionOpen` revokes incoming mesh admission as soon as closing or dedup is set. `isActiveMeshPeer` additionally requires protocol establishment. `ownsActiveMeshLink` requires the exact secured/plain link pointer. Occupancy remains the slot iterator's responsibility. No enum, secondary index, roster deletion, allocation or wall-clock dependency was introduced.

Both receive drivers permit handshake first, then require the exact active owner. Every live application-family drain now requires that owner and checks before taking a queue; both drivers revalidate after every family so retirement during MESSAGE_V2, replica/E2EE admission or repair cannot reach later application work. Families: legacy MESSAGE; signed MESSAGE_V2 and ACK/ACK_CONFIRM; identity/MEMBERSHIP/NICK; channel MODE flags/state/lists; channel/user properties and private read markers; E2EEGROUP and receipts; TOPIC; origin-rejection audit; clone counts; oper events v1/v2; OBSERVE; KILL; WARD; SEARCH; KEYTRANS; memo/media; repair/RESYNC; migration-consumed/offers; signed session replica and its direct ACK. Handshake output and already-owned byte drainage use separate custody paths.

## Link-only production call paths

- `relayWanted` / `relayWantedBySessionReplica` are reached only by guarded `relayLegacyToPeers`. `remoteWhoisFromLink` and `linkChannelHasMember` are reached by guarded WHOIS/member selectors.
- `sendChannelListToConn` is reached only by guarded membership burst. `sendKeyTransHeadOn` is reached by guarded mesh burst; its other two callers are standalone unit encoder tests. `sendCloneAntiEntropy` checks the exact active owner itself.
- `queueDeferredSessionMeshAnnouncementsTo` is called only by guarded `flushDeferredSessionMeshAnnouncements`; real secured output also preflights exact owned link. The isolated capture encoder test does not represent a physical peer.
- All live `drain*` frame-family helpers accept `ConnState`; only SEARCH and KEYTRANS admitted payload bodies have explicit standalone peer test bridges. Those bridge entry points are test-only. The production wrappers validate ownership before calling the admitted implementation.
- Identity transition publication checks owner BEFORE consuming, NICK/PART/QUIT output and legacy local-membership folding; maintenance and replica reconciliation pass the actual owner.
- `sendSessionReplicaAckV2` requires the same owner as its guarded replica admission caller.

## Raw protocol identity exceptions

`establishedPeerName` remains raw and does not silently acquire active semantics. `activeMeshPeerName` combines it with the shared policy. Raw callers are: active-guarded RESYNC, LINKS, endpoint-linked predicate, peer publication and collection; raw duplicate collision inspection (must inspect retained same-full-key leg); admitted handshake stall classification (admissionOpen first); lifecycle liveness timeout diagnostics/expiration; and test-only failure diagnostics. RECV health refresh and dial-success credit now use active name. SQUIT selects an active survivor first, then only a nonretiring named handshake as an explicit cancellation fallback.

## Retained-state exceptions

- SEND completion, raced RECV/cancel, pressure retry, deadline retirement and final close inspect held buffers and kernel references. They move already-owned bytes and release storage, without authoring application frames.
- Netsplit cleanup and dropped-origin cleanup intentionally inspect old roster. Dedup teardown suppresses netsplit. Candidate Helix roster restoration discards transitions and publishes only after complete adopt commit; sealing still refuses incomplete drain rather than hiding it.
- Independently accepted signed session/relay stores retain their authority/custody after transport loss. Their next transmission still selects an active physical route.
- Published peer identities stage replacement completely; OOM keeps the previous snapshot. Reciprocal survivor identity is same full authenticated key, and cached names/key copies cannot select a retiring physical connection.
- `s2s_links_active` remains the existing protocol-established transport gauge until final close. INFO/LINKS/topology and authority use the active policy; class counts remain physical socket/client classification. No stats leaf change is included.

## Classified function index

| Function (server.zig line) | Classification |
|---|---|
| `initReactor` (4613) | Handshake / configured dial control |
| `initInPlace` (4762) | Handshake / configured dial control |
| `e2eeGroupExpectsExternalPeers` (5397) | Independent accepted record / signed authority |
| `e2eeGroupPeerReadiness` (5417) | Shared active policy boundary |
| `injectWebhookPost` (5713) | Physical transport / diagnostic / class metadata |
| `deinit` (6435) | Final-flight custody / teardown / checkpoint |
| `armAccept` (6672) | Handshake / configured dial control |
| `projectOcg2LiveSessions` (6981) | Local attachment / client policy |
| `onTimerTick` (7024) | Final-flight custody / teardown / checkpoint |
| `resyncMeshStateToPeers` (7201) | Shared active policy boundary |
| `pruneStaleMeshMembers` (7245) | Shared active policy boundary |
| `clearDroppedPeerRouteOrigin` (7261) | Final-flight custody / teardown / checkpoint |
| `tallyRegisteredLocalClients` (7322) | Local attachment / client policy |
| `maybeWriteStats` (7338) | Physical transport / diagnostic / class metadata |
| `buildStatusJson` (7736) | Physical transport / diagnostic / class metadata |
| `sweepTimeouts` (8014) | Final-flight custody / teardown / checkpoint |
| `s2sBoundPort` (8123) | Handshake / configured dial control |
| `captureLiveUpgradeForTest` (8249) | Final-flight custody / teardown / checkpoint |
| `handleAccept` (8930) | Handshake / configured dial control |
| `penalizePeer` (9649) | Physical transport / diagnostic / class metadata |
| `s2sSecured` (9662) | Handshake / configured dial control |
| `newSecuredLink` (9678) | Handshake / configured dial control |
| `bindRelayV2UnboundIfReady` (9752) | Shared active policy boundary |
| `noteS2sEstablished` (9799) | Physical transport / diagnostic / class metadata |
| `driveS2sSecured` (9813) | Shared active policy boundary |
| `sendLocalOperBurstTo` (10012) | Shared active policy boundary |
| `sendMeshWardsTo` (10054) | Shared active policy boundary |
| `rebroadcastLocalOpers` (10091) | Inherited active selector / output contract |
| `driveS2s` (10104) | Shared active policy boundary |
| `drainRepairResync` (10201) | Shared active policy boundary |
| `handleConnect` (10229) | Handshake / configured dial control |
| `driveClientBytes` (10295) | Final-flight custody / teardown / checkpoint |
| `handleKtlsRxControl` (10429) | Final-flight custody / teardown / checkpoint |
| `handleRecv` (10525) | Final-flight custody / teardown / checkpoint |
| `handleSend` (10616) | Final-flight custody / teardown / checkpoint |
| `beginDeliveryGapAbort` (10694) | Final-flight custody / teardown / checkpoint |
| `revokeAttachedSessionOnLocalOwner` (10825) | Local attachment / client policy |
| `relayToPeers` (11780) | Inherited active selector / output contract |
| `relayLegacyToPeers` (11790) | Shared active policy boundary |
| `hasSecureRelayV2Peer` (11821) | Shared active policy boundary |
| `relayWanted` (11835) | Inherited active selector / output contract |
| `relayWantedBySessionReplica` (11851) | Inherited active selector / output contract |
| `relayDirectMessagePolicyBlocks` (11864) | Independent accepted record / signed authority |
| `hasEstablishedPeer` (11889) | Shared active policy boundary |
| `relayOriginIsDirectPeer` (11911) | Shared active policy boundary |
| `relayOriginAuth` (11937) | Independent accepted record / signed authority |
| `recordRelaySignatureReject` (11961) | Physical transport / diagnostic / class metadata |
| `meshNickHomeNode` (11976) | Shared active policy boundary |
| `trustedRemoteAccountAtNode` (12021) | Shared active policy boundary |
| `replicatedSessionProof` (12091) | Independent accepted record / signed authority |
| `recordRelayHomeMismatch` (12255) | Physical transport / diagnostic / class metadata |
| `recordRelayUnknownHomeV1` (12266) | Physical transport / diagnostic / class metadata |
| `signRelayOrigin` (12285) | Independent accepted record / signed authority |
| `relayOriginServerName` (12415) | Shared active policy boundary |
| `isVerifiedWebhookRelay` (12438) | Independent accepted record / signed authority |
| `deferRelayV2` (12886) | Independent accepted record / signed authority |
| `sendRelayV2AckToPeer` (12924) | Shared active policy boundary |
| `sendRelayV2AckConfirmToPeer` (12949) | Shared active policy boundary |
| `drainRelayV2Acks` (13021) | Shared active policy boundary |
| `replayRelayV2WireToPeer` (13138) | Shared active policy boundary |
| `drainRelayV2` (13257) | Shared active policy boundary |
| `deliverRelayV2` (13293) | Independent accepted record / signed authority |
| `deliverRelay` (13775) | Inherited active selector / output contract |
| `deliverRelayWhisper` (14172) | Independent accepted record / signed authority |
| `armConnect` (14245) | Handshake / configured dial control |
| `closeConn` (14451) | Final-flight custody / teardown / checkpoint |
| `challengeRequired` (15014) | Local attachment / client policy |
| `processLiveLine` (15233) | Local attachment / client policy |
| `handoffLiveSessionIdentity` (15836) | Local attachment / client policy |
| `deliverChannelBatchGated` (15947) | Local attachment / client policy |
| `netsplitOnPeerDrop` (15962) | Final-flight custody / teardown / checkpoint |
| `sendMeshStateBurstTo` (16014) | Shared active policy boundary |
| `flushMeshBurstStage` (16083) | Final-flight custody / teardown / checkpoint |
| `setChannelModeFlagBits` (16184) | Admitted application payload operation |
| `sendMembershipBurstTo` (16198) | Shared active policy boundary |
| `sendChannelModeFlagsBurstTo` (16284) | Shared active policy boundary |
| `sendChannelModeStateBurstTo` (16387) | Shared active policy boundary |
| `announceChannelModeState` (16402) | Shared active policy boundary |
| `burstPropOrigin` (16589) | Independent accepted record / signed authority |
| `burstEntityPropOrigin` (16815) | Independent accepted record / signed authority |
| `announceEntityProp` (16844) | Shared active policy boundary |
| `recordEntityPropSignatureReject` (17120) | Admitted application payload operation |
| `recordEntityPropAuthorityReject` (17236) | Admitted application payload operation |
| `applyRemoteEntityProp` (17252) | Admitted application payload operation |
| `drainEntityPropChanges` (17381) | Shared active policy boundary |
| `sendEntityPropBurstTo` (17403) | Shared active policy boundary |
| `sendChannelPropBurstTo` (17432) | Shared active policy boundary |
| `sendChannelListToConn` (17486) | Inherited active selector / output contract |
| `announceMembership` (17506) | Shared active policy boundary |
| `announceChannelModeFlags` (17529) | Shared active policy boundary |
| `announceChannelList` (17552) | Shared active policy boundary |
| `announceChannelProp` (17589) | Shared active policy boundary |
| `membershipIdentityOf` (17620) | Local attachment / client policy |
| `nickIsLiveLocal` (17644) | Local attachment / client policy |
| `localNickSameAccount` (17655) | Local attachment / client policy |
| `assignConnClass` (17669) | Physical transport / diagnostic / class metadata |
| `s2sSendqCap` (17694) | Physical transport / diagnostic / class metadata |
| `matchCtx` (17702) | Physical transport / diagnostic / class metadata |
| `broadcastCloneCounts` (17818) | Shared active policy boundary |
| `drainCloneCountsFrom` (17859) | Shared active policy boundary |
| `sendCloneAntiEntropy` (17873) | Shared active policy boundary |
| `countClassMembers` (17897) | Physical transport / diagnostic / class metadata |
| `classCounts` (17925) | Physical transport / diagnostic / class metadata |
| `remoteMemberStatusInChannel` (17979) | Shared active policy boundary |
| `emitRemoteMembership` (18100) | Admitted application payload operation |
| `remoteNickInChannel` (18144) | Shared active policy boundary |
| `emitRemoteQuit` (18184) | Admitted application payload operation |
| `nickInChannelAnywhere` (18288) | Shared active policy boundary |
| `announceOperPrefixForAccount` (18331) | Shared active policy boundary |
| `announceRemoteOperPrefixForAccount` (18382) | Shared active policy boundary |
| `drainIdentityTransitions` (18446) | Shared active policy boundary |
| `discardIdentityTransitions` (18508) | Final-flight custody / teardown / checkpoint |
| `shouldFoldLegacySessionMembership` (18525) | Admitted application payload operation |
| `foldLegacySessionMembership` (18530) | Admitted application payload operation |
| `drainChannelModeFlagChanges` (18657) | Shared active policy boundary |
| `drainChannelModeStateChanges` (18675) | Shared active policy boundary |
| `drainOriginRejections` (18690) | Shared active policy boundary |
| `applyRemoteChannelModeState` (18703) | Admitted application payload operation |
| `extBitHas` (18812) | Admitted application payload operation |
| `recordChannelPropSignatureReject` (18821) | Admitted application payload operation |
| `drainChannelPropChanges` (18916) | Shared active policy boundary |
| `drainChannelListChanges` (18960) | Shared active policy boundary |
| `drainTopicChanges` (18974) | Shared active policy boundary |
| `emitRemoteNick` (19054) | Admitted application payload operation |
| `announceTopic` (19095) | Shared active policy boundary |
| `localNickSessionToken` (19152) | Local attachment / client policy |
| `localNickResolver` (19164) | Local attachment / client policy |
| `sessionReplicaResidenceDecision` (19194) | Independent accepted record / signed authority |
| `residenceTrusted` (19257) | Independent accepted record / signed authority |
| `residenceVerifier` (19290) | Independent accepted record / signed authority |
| `resolveSessionMembershipToken` (19298) | Independent accepted record / signed authority |
| `sessionTokenResolver` (19331) | Independent accepted record / signed authority |
| `authorizeSessionTokenNick` (19335) | Independent accepted record / signed authority |
| `sessionTokenNickAuthorizer` (19368) | Independent accepted record / signed authority |
| `announceNickChange` (19372) | Shared active policy boundary |
| `sendTopicBurstTo` (19402) | Shared active policy boundary |
| `flushS2sOutbound` (19418) | Final-flight custody / teardown / checkpoint |
| `flushS2sOutboundTo` (19424) | Final-flight custody / teardown / checkpoint |
| `flushSecuredS2sOutboundTo` (19438) | Shared active policy boundary |
| `globalMemberCount` (19571) | Shared active policy boundary |
| `remotePublishedTopic` (19615) | Shared active policy boundary |
| `remoteChannelSecret` (19651) | Shared active policy boundary |
| `remoteOnlyChannelNames` (19679) | Shared active policy boundary |
| `findRemoteWhois` (22196) | Shared active policy boundary |
| `remoteWhoisFromLink` (22214) | Inherited active selector / output contract |
| `remoteMemberChannels` (22333) | Shared active policy boundary |
| `sendKillToOwner` (22539) | Shared active policy boundary |
| `drainKills` (22569) | Shared active policy boundary |
| `applyRemoteKill` (22585) | Admitted application payload operation |
| `publishAccountReadMarker` (23693) | Local attachment / client policy |
| `announceReadMarker` (23710) | Shared active policy boundary |
| `sendReadMarkerBurstTo` (23722) | Shared active policy boundary |
| `attachMeshSearchPeer` (24957) | Explicit standalone test bridge |
| `noteMeshSearchLink` (24967) | Explicit standalone test bridge |
| `dispatchMeshSearchQuery` (25055) | Shared active policy boundary |
| `sendKeyTransHeadOn` (25164) | Inherited active selector / output contract |
| `drainKeyTransHeads` (25174) | Shared active policy boundary |
| `drainKeyTransHeadsAdmitted` (25179) | Admitted application payload operation |
| `drainKeyTransPeer` (25192) | Explicit standalone test bridge |
| `drainMeshSearch` (25206) | Shared active policy boundary |
| `drainMeshSearchAdmitted` (25211) | Admitted application payload operation |
| `drainMeshSearchPeer` (25230) | Explicit standalone test bridge |
| `collectAttachedExactTokenClients` (25966) | Local attachment / client policy |
| `collectAttachedTokenAuthorityClients` (25996) | Local attachment / client policy |
| `projectLocalChannelProjection` (26164) | Local attachment / client policy |
| `mirrorTokenGroupMemberModes` (26325) | Local attachment / client policy |
| `partTokenGroupChannel` (26352) | Local attachment / client policy |
| `configuredListenerSet` (26831) | Final-flight custody / teardown / checkpoint |
| `prepareSessionReplicaUpgradeBoundary` (26877) | Final-flight custody / teardown / checkpoint |
| `openCompatibleUpgradeTarget` (26971) | Final-flight custody / teardown / checkpoint |
| `sealSecuredLink` (27005) | Final-flight custody / teardown / checkpoint |
| `sealSessionRegistry` (27131) | Final-flight custody / teardown / checkpoint |
| `helixWorldRelationIdentity` (27315) | Local attachment / client policy |
| `helixWorldRelationClient` (27328) | Local attachment / client policy |
| `sealMeshRedialUpgradeHint` (27732) | Final-flight custody / teardown / checkpoint |
| `sealShardClients` (27778) | Final-flight custody / teardown / checkpoint |
| `performUpgradeAfterCompatibleTarget` (28249) | Final-flight custody / teardown / checkpoint |
| `inheritedOwningCapsuleFd` (28722) | Final-flight custody / teardown / checkpoint |
| `adoptInheritedSessions` (28882) | Final-flight custody / teardown / checkpoint |
| `deinitInheritedCandidateClients` (31118) | Final-flight custody / teardown / checkpoint |
| `rollbackInheritedS2sBeforeIo` (31181) | Final-flight custody / teardown / checkpoint |
| `primeInheritedS2sRoster` (31469) | Final-flight custody / teardown / checkpoint |
| `adoptInheritedS2sLink` (31500) | Final-flight custody / teardown / checkpoint |
| `publishInheritedS2sLink` (31716) | Final-flight custody / teardown / checkpoint |
| `dialManaged` (31745) | Handshake / configured dial control |
| `handleConnectCmd` (31815) | Handshake / configured dial control |
| `initiateS2sConnectToAddr` (31835) | Handshake / configured dial control |
| `publishMooringBreakerGauge` (31966) | Physical transport / diagnostic / class metadata |
| `meshDialForToken` (32004) | Handshake / configured dial control |
| `meshDialForConn` (32012) | Handshake / configured dial control |
| `noteMeshDialSuccessByName` (32027) | Inherited active selector / output contract |
| `mooringStallReason` (32039) | Shared active policy boundary |
| `sweepMeshAutoConnect` (32141) | Handshake / configured dial control |
| `peerRemoteName` (32195) | Handshake / configured dial control |
| `findSquitVictim` (32201) | Shared active policy boundary |
| `meshBroadcastObserveEvent` (33306) | Shared active policy boundary |
| `drainObserveEvents` (33332) | Shared active policy boundary |
| `reapWardMatches` (33585) | Local attachment / client policy |
| `serverNameJuped` (33827) | Handshake / configured dial control |
| `refuseJupedPeer` (33836) | Handshake / configured dial control |
| `fantasyReply` (34523) | Inherited active selector / output contract |
| `handleClones` (34851) | Local attachment / client policy |
| `handleData` (36583) | Inherited active selector / output contract |
| `relayChannelData` (36893) | Inherited active selector / output contract |
| `relayNickData` (36932) | Inherited active selector / output contract |
| `handleWhisper` (37028) | Inherited active selector / output contract |
| `remoteMemberOfChannel` (37200) | Shared active policy boundary |
| `remoteMemberOfChannelAtNode` (37218) | Shared active policy boundary |
| `linkChannelHasMember` (37239) | Inherited active selector / output contract |
| `relayWhisperRemote` (37250) | Inherited active selector / output contract |
| `meshUserCount` (37881) | Shared active policy boundary |
| `handleLusers` (37896) | Local attachment / client policy |
| `collectExactLogicalClients` (38175) | Local attachment / client policy |
| `localRenderedNickOccupiedExcept` (38589) | Local attachment / client policy |
| `broadcastOperGrant` (39112) | Shared active policy boundary |
| `broadcastMeshWard` (39130) | Shared active policy boundary |
| `drainWards` (39163) | Shared active policy boundary |
| `ingestMeshWardPayload` (39183) | Admitted application payload operation |
| `applyRemoteWard` (39207) | Admitted application payload operation |
| `collectE2eeGroupOutboxPeers` (40667) | Shared active policy boundary |
| `e2eeGroupDirectNeighbor` (40712) | Shared active policy boundary |
| `replayE2eeGroupWireToPeer` (40732) | Shared active policy boundary |
| `sendE2eeGroupAckOnLink` (40829) | Shared active policy boundary |
| `sendE2eeGroupAckToPeer` (40850) | Shared active policy boundary |
| `sendE2eeGroupAckConfirmToPeer` (40874) | Shared active policy boundary |
| `drainE2eeGroup` (41100) | Shared active policy boundary |
| `drainE2eeGroupAcks` (41129) | Shared active policy boundary |
| `appendE2eeGroupRecipient` (41185) | Local attachment / client policy |
| `queueDeferredSessionMeshAnnouncementsTo` (43093) | Inherited active selector / output contract |
| `flushDeferredSessionMeshAnnouncements` (43219) | Shared active policy boundary |
| `flushReadyDeferredSessionMeshAnnouncements` (43370) | Local attachment / client policy |
| `revokeAttachedSessionReserved` (44167) | Local attachment / client policy |
| `trustedReclaimRoute` (44758) | Derived published identity cache |
| `publishCurrentSessionReplicaToken` (45382) | Local attachment / client policy |
| `broadcastSessionReplicaV2` (45703) | Shared active policy boundary |
| `releaseMeshBurstAfterSessionReplicaReplay` (45791) | Shared active policy boundary |
| `replaySessionReplicaStoreTo` (45831) | Shared active policy boundary |
| `resumeSessionReplicaReplays` (45942) | Shared active policy boundary |
| `refreshPortableSessionReplicasV2` (45954) | Local attachment / client policy |
| `refreshAttachedSessionReplicaLeases` (46002) | Local attachment / client policy |
| `broadcastSessionMigration` (46033) | Shared active policy boundary |
| `convergeSessionConsumed` (46050) | Shared active policy boundary |
| `drainSessionMigrationConsumed` (46072) | Shared active policy boundary |
| `sendSessionReplicaAckV2` (46084) | Shared active policy boundary |
| `rebindSessionReplicaRoutes` (46170) | Shared active policy boundary |
| `reconcileSessionReplicaRouteProjection` (46244) | Shared active policy boundary |
| `projectSessionReplicaChannels` (46411) | Local attachment / client policy |
| `drainSessionReplicaV2` (46820) | Shared active policy boundary |
| `drainSessionMigrations` (47038) | Shared active policy boundary |
| `restoreAndBindMigrationSnapshotWithTicket` (47750) | Local attachment / client policy |
| `meshBroadcastMemoPush` (48841) | Shared active policy boundary |
| `drainMemoPushes` (48857) | Shared active policy boundary |
| `meshBroadcastMediaWsDatagram` (48874) | Shared active policy boundary |
| `drainMediaWsDatagrams` (48893) | Shared active policy boundary |
| `installClassRegistry` (50220) | Physical transport / diagnostic / class metadata |
| `meshBroadcastAuthoredOperEventV2` (51399) | Shared active policy boundary |
| `meshBroadcastOperEvent` (51428) | Shared active policy boundary |
| `drainOperEvents` (51454) | Shared active policy boundary |
| `drainOperEventsV2` (51488) | Shared active policy boundary |
| `meshForwardOperEventV2` (51515) | Shared active policy boundary |
| `liveListenerSet` (51581) | Final-flight custody / teardown / checkpoint |
| `infoRuntimeLines` (52127) | Shared active policy boundary |
| `handleLinks` (52224) | Shared active policy boundary |
| `peerDescription` (52267) | Physical transport / diagnostic / class metadata |
| `activeMeshPeerName` (52279) | Shared active policy boundary |
| `establishedPeerName` (52284) | Handshake / configured dial control |
| `meshPeerLinkedByDial` (52295) | Shared active policy boundary |
| `sameS2sPeer` (52308) | Handshake / configured dial control |
| `transferMeshDialBinding` (52323) | Handshake / configured dial control |
| `requestS2sDedupDrain` (52349) | Final-flight custody / teardown / checkpoint |
| `progressS2sDedupDrain` (52361) | Final-flight custody / teardown / checkpoint |
| `resolveS2sCollision` (52414) | Handshake / configured dial control |
| `distinctPeerCount` (52470) | Derived published identity cache |
| `publishPeerCount` (52482) | Shared active policy boundary |
| `storePublishedMeshPeers` (52529) | Derived published identity cache |
| `freePublishedMeshPeers` (52557) | Derived published identity cache |
| `readPeerNames` (52582) | Derived published identity cache |
| `handleMap` (52607) | Derived published identity cache |
| `s2sPeerLivenessExpired` (52707) | Final-flight custody / teardown / checkpoint |
| `maybeProbeMeshPeerRtt` (52716) | Shared active policy boundary |
| `assembleMeshTopology` (52791) | Shared active policy boundary |
| `collectPeerNames` (52914) | Shared active policy boundary |
| `handleTagmsg` (53134) | Inherited active selector / output contract |
| `messageOne` (53919) | Inherited active selector / output contract |
| `isOverrideOper` (54875) | Local attachment / client policy |
| `sendNamesWithProjection` (54897) | Shared active policy boundary |

Per-function reason and exact source pin are in `lifecycle-consumer-classified.json`. No unclassified function remains in the specified search union. This is writer inventory, not independent review or runtime acceptance.
