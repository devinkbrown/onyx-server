let meta = #{
    name: "mesh-scale-audit",
    description: "Audit Undertow mesh tables for fixed peer and node ceilings and grow the ones that refuse past 64",
    when_to_use: "Heavy mesh scale audit. Fixes stay in the owned Undertow files. Does not edit src/daemon/server.zig.",
    phases: [
        #{ title: "Audit", detail: "four read-only lenses over mesh capacity" },
        #{ title: "Confirm", detail: "keep only ceilings that refuse another peer" },
        #{ title: "Fix", detail: "allocator-backed growth and a 65-peer test" },
    ],
};

let finding_schema = #{
    "type": "object",
    "required": ["findings"],
    "properties": #{
        "findings": #{
            "type": "array",
            "maxItems": 6,
            "items": #{
                "type": "object",
                "required": ["file", "line", "symbol", "bug"],
                "properties": #{
                    "file": #{ "type": "string" },
                    "line": #{ "type": "string" },
                    "symbol": #{ "type": "string" },
                    "bug": #{ "type": "string" },
                },
            },
        },
    },
};

let verdict_schema = #{
    "type": "object",
    "required": ["real", "evidence"],
    "properties": #{
        "real": #{ "type": "boolean" },
        "evidence": #{ "type": "string" },
    },
};

let owned = "src/substrate/undertow/route_table.zig src/substrate/undertow/s2s_peer.zig src/substrate/undertow/gossip_round.zig src/substrate/undertow/gossip_views.zig src/substrate/undertow/membership_view.zig src/substrate/undertow/membership_burst.zig src/substrate/undertow/server_registry.zig src/substrate/undertow/mesh.zig src/substrate/undertow/mesh_topology.zig src/substrate/undertow/partition_detector.zig src/substrate/undertow/peer_link.zig";

fn mesh_owned(path) {
    path == "src/substrate/undertow/route_table.zig" || path == "src/substrate/undertow/s2s_peer.zig" || path == "src/substrate/undertow/gossip_round.zig" || path == "src/substrate/undertow/gossip_views.zig" || path == "src/substrate/undertow/membership_view.zig" || path == "src/substrate/undertow/membership_burst.zig" || path == "src/substrate/undertow/server_registry.zig" || path == "src/substrate/undertow/mesh.zig" || path == "src/substrate/undertow/mesh_topology.zig" || path == "src/substrate/undertow/partition_detector.zig" || path == "src/substrate/undertow/peer_link.zig"
}

phase("Audit");
let lenses = [
    "route table fanout and any ChannelFanoutFull or RouteTableFull returned when a channel already holds 64 nodes",
    "gossip rounds, membership bursts, and views that drop or refuse the 65th member, suspicion, or node",
    "server registry, mesh topology, and peer link tables that store peers in a fixed array or return full at 64",
    "partition detector node graph: TooManyNodes and the dense max_nodes matrix",
];
let jobs = [];
for lens in lenses {
    let prompt = "Repository: /home/kain/onyx-server. Undertow is the mesh. ";
    prompt += "Read the shipped code with grep and read_file before you answer. Lens: " + lens + ". ";
    prompt += "Owned files, the only paths you may cite: " + owned + ". ";
    prompt += "A finding is a hard ceiling that refuses, truncates, or overwrites a peer, node, or membership once a fixed count is hit. ";
    prompt += "Cite file, line, and the symbol. Say what the 65th item does. ";
    prompt += "Do not report u64, 64-bit shifts, hash widths, cache lines, IRC nick or channel or account lengths, gossip sample sizes that still store every member, or a ceiling that already accepts more than 64. ";
    prompt += "Do not report src/daemon/server.zig. Empty findings is correct when this lens has no such ceiling. At most 6 findings.";
    jobs.push(#{
        prompt: prompt,
        label: "audit:" + lens.sub_string(0, 28),
        capability_mode: "read-only",
        output_schema: finding_schema,
    });
}
let results = parallel(jobs);

let raw = [];
for r in results {
    if r != () && r.success && r.output != () && r.output.findings != () {
        for f in r.output.findings {
            if f != () && f.file != () && f.bug != () && f.symbol != () && mesh_owned(f.file) {
                if raw.len() < 12 {
                    raw.push(f);
                } else {
                    log("dropped finding over the confirm cap " + f.file);
                }
            } else if f != () && f.file != () {
                log("dropped out-of-scope finding " + f.file);
            }
        }
    }
}

phase("Confirm");
if raw.len() == 0 {
    let empty = "Mesh scale audit\n\nNo owned file refuses a 65th peer, node, or membership.\n";
    write_scratch_file("mesh-scale-audit.md", empty);
    complete(#{ summary: "No confirmed mesh peer ceiling in the owned files.", findings: 0 });
}

let vjobs = [];
for f in raw {
    let prompt = "Repository: /home/kain/onyx-server. Read " + f.file + " around the cited line before you answer. ";
    prompt += "Claim: " + f.bug + " Symbol: " + f.symbol + ". ";
    prompt += "Set real=true only if the shipped function refuses, truncates, or overwrites a peer, node, or membership at a fixed bound of 64, or the partition detector refuses another node because of its dense max_nodes matrix. ";
    prompt += "Set real=false for IRC name lengths, protocol bit widths, sample sizes that keep every member, and ceilings that already admit more than 64. ";
    prompt += "evidence is the function name and the branch that returns full or drops the extra item.";
    vjobs.push(#{
        prompt: prompt,
        label: "confirm:" + f.symbol.sub_string(0, 24),
        capability_mode: "read-only",
        output_schema: verdict_schema,
    });
}
let verdicts = parallel(vjobs);

let findings = [];
let i = 0;
for v in verdicts {
    if v != () && v.success && v.output != () && v.output.real == true && v.output.evidence != () && v.output.evidence != "" {
        findings.push(raw[i]);
    }
    i += 1;
}
log(findings.len().to_string() + " confirmed of " + raw.len().to_string());

let report = "Mesh scale audit\n\n";
if findings.len() == 0 {
    report += "Audit hits did not survive confirmation.\n";
    write_scratch_file("mesh-scale-audit.md", report);
    complete(#{ summary: "No confirmed mesh peer ceiling.", findings: 0 });
}
for f in findings {
    report += f.file + ":" + f.line + " " + f.symbol + " " + f.bug + "\n\n";
}
write_scratch_file("mesh-scale-audit.md", report);

phase("Fix");
let fix_prompt = "Repository: /home/kain/onyx-server. You are in a private worktree. Fix only the confirmed mesh ceilings in this JSON, and only if the current source still refuses or truncates. JSON: ";
fix_prompt += json_encode(findings);
fix_prompt += " Owned files, the only files you may edit: " + owned + ". ";
fix_prompt += "Peer counts, node ids, and membership rows must grow from the allocator. Do not return a full or fanout error at 64, and do not truncate the 65th. A test must admit 65 items through the shipped function. ";
fix_prompt += "If partition_detector is in the JSON, replace the dense n-by-n matrix with a sparse allocator-backed edge list. Do not allocate a squared matrix for the larger cap. ";
fix_prompt += "Do not edit resolveIncomingNick, identityNickClaim, or the sticky-trust path in route_table.zig. Do not edit src/daemon/server.zig. Do not change IRC nick, channel, account, or key lengths. Do not change u64 widths, replay bitmaps that are not peer lists, or gossip sample sizes that already store every member. ";
fix_prompt += "Do not enable FEC, kTLS txrx, live OCSP, defer_taskrun, or MESSAGE_V2 active. Zig 0.17, no C, no std.heap.GeneralPurposeAllocator. Use std.testing.allocator in tests. Run zig fmt on each file you change. ";
fix_prompt += "Tests: export ZIG_GLOBAL_CACHE_DIR=\"$PWD/.zig-cache\" and run zig build test-mod-verbose with a -Dtest-filter that names the new test. Do not commit. Do not push. Do not touch /home/kain/onyx-server-run or signal any service. ";
fix_prompt += "Then git add only the owned files you changed and run git diff --cached > /tmp/grok-goal-087b6870ad2c/implementer/mesh-scale-grok.patch. ";
fix_prompt += "Return the patch path, the test command, the pass count, and any finding you left because it was not a peer ceiling.";
let fixed = agent(fix_prompt, #{
    label: "fix-mesh-scale",
    capability_mode: "execute",
    isolation_worktree: true,
});
if fixed != () && fixed.success {
    complete(#{ summary: "Mesh scale fix lane finished", findings: findings.len(), fixer: fixed.output });
}
complete(#{ summary: "Mesh ceilings recorded; fixer did not succeed", findings: findings.len() });
