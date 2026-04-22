import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./sheets.css";

function bufferToBase64(buffer: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

async function encryptPassword(plaintext: string, encryptionKeyHex: string) {
    const keyBytes = Uint8Array.from(encryptionKeyHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
    return {
        password: bufferToBase64(ciphertext),
        iv: bufferToBase64(iv.buffer),
        salt: bufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer),
    };
}

function AddPassword() {
    const navigate = useNavigate();
    const [account, setAccount] = useState("");
    const [password, setPassword] = useState("");
    const [statusMsg, setStatusMsg] = useState("");
    const [isSuccess, setIsSuccess] = useState(false);
    const [loading, setLoading] = useState(false);

    async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        setStatusMsg(""); setIsSuccess(false);
        if (!account || !password) { setStatusMsg("Please fill in all fields."); return; }

        const encryptionKey = sessionStorage.getItem("encryptionKey");
        if (!encryptionKey) { navigate("/"); return; }

        setLoading(true);
        try {
            const { password: encryptedPassword, iv, salt } = await encryptPassword(password, encryptionKey);
            const response = await fetch("http://localhost:8000/vault", {
                method: "POST", credentials: "include",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ account, password: encryptedPassword, iv, salt }),
            });

            if (!response.ok) {
                const data = await response.json();
                setStatusMsg(data.detail ?? "Failed to save entry.");
                return;
            }

            setIsSuccess(true);
            setStatusMsg("Password saved!");
            setAccount(""); setPassword("");
        } catch {
            setStatusMsg("Encryption or network error. Please try again.");
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="page">
            <div className="topbar">
                <span className="topbar-logo">pw<span>vault</span></span>
                <div className="topbar-actions">
                    <button className="btn-ghost" onClick={() => navigate("/UserMenu")}>← Back</button>
                </div>
            </div>

            <div className="center-layout">
                <div className="card">
                    <div className="card-title">Add credential</div>
                    <div className="card-subtitle">ENCRYPTED BEFORE LEAVING YOUR BROWSER</div>

                    <form onSubmit={handleSubmit} style={{ display:"flex", flexDirection:"column", gap:0, maxWidth:"none", width:"100%", alignSelf:"unset" }}>
                        <div className="field">
                            <label htmlFor="account">Account / Service</label>
                            <input type="text" id="account" value={account} onChange={e => setAccount(e.target.value)} placeholder="e.g. Netflix, Gmail" />
                        </div>
                        <div className="field">
                            <label htmlFor="password">Password</label>
                            <input type="password" id="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••••••" />
                        </div>

                        {statusMsg && <div className={`msg ${isSuccess ? "msg-success" : "msg-error"}`}>{statusMsg}</div>}

                        <button type="submit" className="btn-primary" style={{ marginTop: 20 }} disabled={loading}>
                            {loading ? "Encrypting…" : "Save password"}
                        </button>
                    </form>
                </div>
            </div>

            <footer><p>© Password Vault 2026</p></footer>
        </div>
    );
}

export default AddPassword;