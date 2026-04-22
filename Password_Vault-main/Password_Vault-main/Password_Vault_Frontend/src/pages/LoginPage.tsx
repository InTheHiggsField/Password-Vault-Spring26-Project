import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
    bufferToHex,
    deriveEncryptionKeyOnly,
    deriveMasterKeys,
    hexToBuffer,
} from "../utils/crypto";
import "./sheets.css";

export default function LoginPage() {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [errMsg, setErrMsg] = useState("");
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        setErrMsg("");
        if (!email || !password) { setErrMsg("Please fill in all fields."); return; }

        setLoading(true);
        try {
            let saltResponse;
            try {
                saltResponse = await fetch(`http://localhost:8000/auth/get-salt?email=${encodeURIComponent(email)}`);
            } catch {
                setErrMsg("Network error while retrieving salt. Please try again.");
                return;
            }

            if (!saltResponse.ok) { setErrMsg("Failed to retrieve salt. Please try again."); return; }

            const saltHex = (await saltResponse.json()).salt;
            let salt: Uint8Array;
            try { salt = hexToBuffer(saltHex); }
            catch { setErrMsg("Invalid salt received from server."); return; }

            const isBackfillCase = saltHex === "00".repeat(16);
            const { authKey, encryptionKey } = await deriveMasterKeys(password, salt);

            let oldEncryptionKey: ArrayBuffer | null = null;
            if (isBackfillCase) {
                oldEncryptionKey = await deriveEncryptionKeyOnly(
                    password, new TextEncoder().encode(email), 600000
                );
            }

            const response = await fetch("http://localhost:8000/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: "include",
                body: JSON.stringify({ email, username: "", hashed_password: bufferToHex(authKey) }),
            });

            if (response.status === 429) { setErrMsg("Too many login attempts. Please wait 5 minutes."); return; }
            if (response.status === 401) { setErrMsg("Invalid email or password."); return; }
            if (!response.ok) { setErrMsg("Server error. Please try again later."); return; }

            const data = await response.json();
            sessionStorage.setItem("encryptionKey", bufferToHex(encryptionKey));
            sessionStorage.setItem("userId", String(data.user_id));
            sessionStorage.setItem("username", data.username);
            sessionStorage.setItem("email", email);

            if (isBackfillCase && oldEncryptionKey) {
                try { await reEncryptVaultEntries(oldEncryptionKey, encryptionKey); }
                catch (err) { console.error("Re-encryption failed:", err); }
            }

            navigate("/UserMenu");
        } catch (err) {
            console.error("Login error:", err);
            setErrMsg("Something went wrong. Please try again.");
        } finally {
            setLoading(false);
        }
    }

    async function reEncryptVaultEntries(oldKey: ArrayBuffer, newKey: ArrayBuffer) {
        const res = await fetch("http://localhost:8000/vault", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to fetch vault entries");
        const entries = await res.json();

        for (const entry of entries) {
            const iv = Uint8Array.from(atob(entry.iv), c => c.charCodeAt(0));
            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                await crypto.subtle.importKey("raw", oldKey, { name: "AES-GCM" }, false, ["decrypt"]),
                Uint8Array.from(atob(entry.password), c => c.charCodeAt(0))
            );
            const newIv = crypto.getRandomValues(new Uint8Array(12));
            const reencrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: newIv },
                await crypto.subtle.importKey("raw", newKey, { name: "AES-GCM" }, false, ["encrypt"]),
                decrypted
            );
            await fetch(`http://localhost:8000/vault/entry/${entry.id}`, {
                method: "PUT", headers: { "Content-Type": "application/json" }, credentials: "include",
                body: JSON.stringify({
                    account: entry.account,
                    password: btoa(String.fromCharCode(...new Uint8Array(reencrypted))),
                    iv: btoa(String.fromCharCode(...newIv)),
                    salt: entry.salt,
                }),
            });
        }
    }

    return (
        <div className="page">
            <div className="topbar">
                <span className="topbar-logo">pw<span>vault</span></span>
            </div>

            <div className="center-layout">
                <div className="card">
                    <div className="card-title">Sign in</div>
                    <div className="card-subtitle">ZERO-KNOWLEDGE · END-TO-END ENCRYPTED</div>

                    <form onSubmit={handleSubmit} style={{ display:"flex", flexDirection:"column", gap:0, maxWidth:"none", width:"100%", alignSelf:"unset" }}>
                        <div className="field">
                            <label htmlFor="email">Email</label>
                            <input type="email" id="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" />
                        </div>
                        <div className="field">
                            <label htmlFor="password">Master Password</label>
                            <input type="password" id="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••••••" />
                        </div>

                        {errMsg && <div className="msg msg-error">{errMsg}</div>}

                        <button type="submit" className="btn-primary" style={{ marginTop: 20 }} disabled={loading}>
                            {loading ? "Deriving keys…" : "Sign in"}
                        </button>
                    </form>

                    <div className="divider" />
                    <div style={{ textAlign:"center" }}>
                        <span style={{ fontSize:12, color:"var(--text-muted)" }}>No account? </span>
                        <button className="text-link" onClick={() => navigate("/NewAccount")}>Create one</button>
                    </div>
                </div>
            </div>

            <footer><p>© Password Vault 2026</p></footer>
        </div>
    );
}