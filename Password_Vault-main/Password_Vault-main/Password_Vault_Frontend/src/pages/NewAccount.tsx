import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { passwordFormatErr, passwordFormatMsg, passwordMatchMsg } from "../App";
import { bufferToHex, deriveMasterKeys, generateRandomSalt } from "../utils/crypto";
import "./sheets.css";

function NewAccount() {
    const navigate = useNavigate();
    const [email, setEmail] = useState("");
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [password2, setPassword2] = useState("");
    const [statusMsg, setStatusMsg] = useState("");
    const [isSuccess, setIsSuccess] = useState(false);
    const [loading, setLoading] = useState(false);

    async function newUserSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        setStatusMsg(""); setIsSuccess(false);

        if (!email || !username || !password) { setStatusMsg("Please fill in all fields."); return; }
        if (passwordFormatErr(password) !== 0b11111) { setStatusMsg("Password does not meet requirements."); return; }
        if (password !== password2) { setStatusMsg("Passwords do not match."); return; }

        setLoading(true);
        try {
            const salt = generateRandomSalt();
            const { authKey, encryptionKey } = await deriveMasterKeys(password, salt);

            const response = await fetch("http://localhost:8000/auth/signup", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: "include",
                body: JSON.stringify({ email, username, hashed_password: bufferToHex(authKey), salt: bufferToHex(salt.buffer as ArrayBuffer) }),
            });

            if (response.status === 429) { setStatusMsg("Too many attempts. Please wait 3 minutes."); return; }
            if (!response.ok) {
                const data = await response.json();
                setStatusMsg(data.detail ?? "Registration failed. Please try again.");
                return;
            }

            const data = await response.json();
            sessionStorage.setItem("encryptionKey", bufferToHex(encryptionKey));
            sessionStorage.setItem("userId", String(data.user_id));
            sessionStorage.setItem("username", username);
            sessionStorage.setItem("email", email);
            setIsSuccess(true);
            setStatusMsg("Account created!");
            setTimeout(() => navigate("/UserMenu"), 800);
        } catch (err) {
            console.error("Registration error:", err);
            setStatusMsg("Something went wrong. Please try again.");
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="page">
            <div className="topbar">
                <span className="topbar-logo">pw<span>vault</span></span>
            </div>

            <div className="center-layout">
                <div className="card">
                    <div className="card-title">Create account</div>
                    <div className="card-subtitle">YOUR KEY NEVER LEAVES THIS DEVICE</div>

                    <form onSubmit={newUserSubmit} style={{ display:"flex", flexDirection:"column", gap:0, maxWidth:"none", width:"100%", alignSelf:"unset" }}>
                        <div className="field">
                            <label htmlFor="email">Email</label>
                            <input type="email" id="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" />
                        </div>
                        <div className="field">
                            <label htmlFor="username">Username</label>
                            <input type="text" id="username" value={username} onChange={e => setUsername(e.target.value)} placeholder="yourname" />
                        </div>
                        <div className="field">
                            <label htmlFor="new-password">Master Password</label>
                            <input type="password" id="new-password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••••••" />
                        </div>
                        <div className="field">
                            <label htmlFor="new-password2">Confirm Password</label>
                            <input type="password" id="new-password2" value={password2} onChange={e => setPassword2(e.target.value)} placeholder="••••••••••••" />
                        </div>

                        {password && <ul className="validation-list">{passwordFormatMsg(password)}</ul>}
                        {password2 && password !== password2 && (
                            <div className="msg msg-error" style={{ marginTop: 8 }}>{passwordMatchMsg(password, password2)}</div>
                        )}
                        {statusMsg && <div className={`msg ${isSuccess ? "msg-success" : "msg-error"}`}>{statusMsg}</div>}

                        <button type="submit" className="btn-primary" style={{ marginTop: 20 }} disabled={loading}>
                            {loading ? "Creating account…" : "Create account"}
                        </button>
                    </form>

                    <div className="divider" />
                    <div style={{ textAlign:"center" }}>
                        <span style={{ fontSize:12, color:"var(--text-muted)" }}>Have an account? </span>
                        <button className="text-link" onClick={() => navigate("/")}>Sign in</button>
                    </div>
                </div>
            </div>

            <footer><p>© Password Vault 2026</p></footer>
        </div>
    );
}

export default NewAccount;