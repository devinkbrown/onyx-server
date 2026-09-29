let meta = #{
    name: "armor-tls-audit",
    description: "Audit Armor TLS for fail-open bugs and fix only confirmed defects in the handshake and certificate files",
    when_to_use: "Heavy Armor TLS audit. Fixes stay in src/crypto handshake and X.509 files. Does not edit src/daemon/server.zig.",
    phases: [
        #{ title: "Audit", detail: "four read-only lenses over Armor" },
        #{ title: "Fix", detail: "patch confirmed bugs in the owned files" },
    ],
};

let finding_schema = #{
    "type": "object",
    "required": ["findings"],
    "properties": #{
        "findings": #{
            "type": "array",
            "maxItems": 8,
            "items": #{
                "type": "object",
                "required": ["file", "line", "bug", "impact"],
                "properties": #{
                    "file": #{ "type": "string" },
                    "line": #{ "type": "string" },
                    "bug": #{ "type": "string" },
                    "impact": #{ "type": "string" },
                },
            },
        },
    },
};

let owned = "src/crypto/tls.zig src/crypto/tls_server.zig src/crypto/tls_client.zig src/crypto/tls_record.zig src/crypto/tls_resumption.zig src/crypto/x509.zig src/crypto/x509_verify.zig src/crypto/x509_props.zig";

phase("Audit");
let lenses = [
    "TLS 1.3 server and client handshake: skipped CertificateVerify, early data acceptance, KeyUpdate, alert downgrade, transcript binding",
    "record layer: nonce reuse, content-type confusion, length and padding oracles, sequence wrap",
    "X.509 path building: name constraints, critical extensions, time validity, wildcard and SAN mismatch, weak signature acceptance",
    "resumption and exporters: ticket lifetime, binder checks, 0-RTT replay, exporter transcript binding",
];
let jobs = [];
for lens in lenses {
    let prompt = "Repository: /home/kain/onyx-server. Armor is the pure-Zig TLS stack under src/crypto/. ";
    prompt += "Read the shipped code with grep and read_file before you answer. Lens: " + lens + ". ";
    prompt += "Report only defects you can point at with a file path and a line number in these files: " + owned + ". ";
    prompt += "A finding is a fail-open check, a skipped verify, a nonce or transcript mixup, or an accept of a certificate the path builder should reject. ";
    prompt += "Do not report style, naming, or missing roadmap features. Do not propose kTLS txrx, live OCSP enablement, FEC, or a new TLS version. ";
    prompt += "Do not write exploit programs, payloads, or attack procedures. Empty findings is correct when the lens is clean. At most 8 findings.";
    jobs.push(#{
        prompt: prompt,
        label: "audit:" + lens.sub_string(0, 24),
        capability_mode: "read-only",
        output_schema: finding_schema,
    });
}
let results = parallel(jobs);

let findings = [];
for r in results {
    if r != () && r.success && r.output != () && r.output.findings != () {
        for f in r.output.findings {
            if f != () && f.file != () && f.bug != () {
                let path = f.file;
                let allowed = path == "src/crypto/tls.zig" || path == "src/crypto/tls_server.zig" || path == "src/crypto/tls_client.zig" || path == "src/crypto/tls_record.zig" || path == "src/crypto/tls_resumption.zig" || path == "src/crypto/x509.zig" || path == "src/crypto/x509_verify.zig" || path == "src/crypto/x509_props.zig";
                if allowed {
                    findings.push(f);
                } else {
                    log("dropped out-of-scope finding " + path);
                }
            }
        }
    }
}

let report = "Armor TLS audit\n\n";
if findings.len() == 0 {
    report += "No confirmed defect in the owned handshake and certificate files.\n";
    write_scratch_file("armor-tls-audit.md", report);
    complete(#{ summary: "No confirmed Armor TLS defects in the owned files.", findings: 0 });
}
for f in findings {
    report += f.file + ":" + f.line + " " + f.bug + "\nImpact: " + f.impact + "\n\n";
}
write_scratch_file("armor-tls-audit.md", report);
log(findings.len().to_string() + " in-scope findings");

phase("Fix");
let fix_prompt = "Repository: /home/kain/onyx-server. You are in a private worktree. Fix only the confirmed Armor defects in this JSON, and only if you can still see the bug in the current source. JSON: ";
fix_prompt += json_encode(findings);
fix_prompt += " Owned files, the only files you may edit: " + owned + ". ";
fix_prompt += "Do not edit src/daemon/server.zig, src/daemon/config_boot.zig, src/daemon/config_format.zig, src/daemon/dispatch.zig, src/daemon/services.zig, src/proto/sasl.zig, docs/reference/config.md, or any ktls, tls_conn, tls12, aead, hkdf, or ocsp file. ";
fix_prompt += "Do not enable kTLS txrx, live OCSP, defer_taskrun, or MESSAGE_V2 active. Do not add exploit programs. A regression test must call the shipped function and expect the closed behavior. ";
fix_prompt += "Zig 0.17, no C, no std.heap.GeneralPurposeAllocator. Use std.testing.allocator in tests. Run zig fmt on each file you change. ";
fix_prompt += "Tests: export ZIG_GLOBAL_CACHE_DIR=\"$PWD/.zig-cache\" and run zig build test-tls-verbose. Do not commit. Do not push. Do not touch /home/kain/onyx-server-run or signal any service. ";
fix_prompt += "Then git add only the owned files you changed and run git diff --cached > /tmp/grok-goal-087b6870ad2c/implementer/armor-grok.patch. ";
fix_prompt += "Return the patch path, the test command, the pass count, and any finding you refused because the code was already safe.";
let fixed = agent(fix_prompt, #{
    label: "fix-armor",
    capability_mode: "execute",
    isolation_worktree: true,
});
if fixed != () && fixed.success {
    complete(#{ summary: "Armor fix lane finished", findings: findings.len(), fixer: fixed.output });
}
complete(#{ summary: "Armor findings recorded; fixer did not succeed", findings: findings.len() });
