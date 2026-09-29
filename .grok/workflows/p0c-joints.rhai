let meta = #{
    name: "p0c-joints",
    description: "Implement the GAP-P0c reaction tally so a subscriber who joins late can read it",
    when_to_use: "Section 13 joint after P0b. Reaction tally only. Does not edit KNOCK or Armor.",
    phases: [
        #{ title: "Read", detail: "locate the shipped reaction path" },
        #{ title: "Implement", detail: "store a tally and test the late subscriber" },
    ],
};

let read_schema = #{
    "type": "object",
    "required": ["store_file", "emit_file", "query_gap"],
    "properties": #{
        "store_file": #{ "type": "string" },
        "emit_file": #{ "type": "string" },
        "query_gap": #{ "type": "string" },
    },
};

phase("Read");
let reader_prompt = "Repository: /home/kain/onyx-server. Read src/proto/activity.zig and src/daemon/server.zig function pushReactionActivity (search for that name; do not rewrite the file). ";
reader_prompt += "GAP-P0c says pushReactionActivity emits ACTIVITY only to current subscribers and returns when there are none, so a subscriber who joins late cannot see a reaction tally. ";
reader_prompt += "Report store_file as the file that already describes the reaction CRDT, emit_file as src/daemon/server.zig, and query_gap as one sentence naming the missing read path. Use grep and read_file. Do not edit anything.";
let located = agent(reader_prompt, #{
    label: "locate-reaction",
    capability_mode: "read-only",
    output_schema: read_schema,
});
if located == () || located.success != true || located.output == () || located.output.store_file == () {
    complete(#{ summary: "Could not locate the reaction path.", implemented: false });
}

phase("Implement");
let impl = "Repository: /home/kain/onyx-server. You are in a private worktree. Implement GAP-P0c's reaction bullet only: a reaction tally with a stable target, an add and a remove, and a read a subscriber can do after joining late. ";
impl += "The locate step said store=" + located.output.store_file + " emit=" + located.output.emit_file + " gap=" + located.output.query_gap + ". ";
impl += "Drive the shipped entry point. Do not start the assertion after a hand-built tally that production never writes. ";
impl += "You may edit src/proto/activity.zig, src/daemon/activity_subscriptions.zig, and only the pushReactionActivity function plus one new test in src/daemon/server.zig. ";
impl += "Do not edit handleKnock, completeIrcxAuth, mesh peer publication, oauth, sasl, config_boot, config_format, dispatch.zig, services.zig, or src/proto/sasl.zig. ";
impl += "Do not edit src/crypto or src/daemon/ktls.zig, tls_conn.zig, tls_certs.zig, ocsp_staple.zig. ";
impl += "Do not deploy, do not signal onyx-server.service, do not edit /home/kain/onyx-server-run. Do not enable live mail. ";
impl += "Zig 0.17. No std.heap.GeneralPurposeAllocator. error.SkipZigTest is one identifier with no space. A defer block has no trailing semicolon. zig fmt every file you touch. ";
impl += "Test with ZIG_GLOBAL_CACHE_DIR=\"$PWD/.zig-cache\" zig build test-mod-verbose -Dtest-filter='GAP-P0c reaction'. The test name must contain that substring and must print the tally the late subscriber observes. ";
impl += "Do not commit. git add only the files you were allowed to edit, then git diff --cached > /tmp/grok-goal-087b6870ad2c/implementer/p0c-reaction.patch. ";
impl += "Return whether the test passed and the patch path.";
let done = agent(impl, #{
    label: "implement-tally",
    capability_mode: "execute",
    isolation_worktree: true,
});
if done != () && done.success {
    complete(#{ summary: "Reaction tally lane finished", result: done.output });
}
complete(#{ summary: "Reaction tally lane did not succeed", implemented: false });
