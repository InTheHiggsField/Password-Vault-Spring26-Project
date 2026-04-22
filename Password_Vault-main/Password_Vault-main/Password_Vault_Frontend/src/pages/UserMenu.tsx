import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { passwordFormatErr, passwordFormatMsg, passwordMatchMsg } from "../App";
import { bufferToHex, deriveMasterKeys, generateRandomSalt, hexToBuffer } from "../utils/crypto";
import "./sheets.css";

const API = "http://localhost:8000";

function bufferToBase64(buffer: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(b64: string): ArrayBuffer {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

async function reEncryptAllEntries(
    oldEncryptionKeyHex: string,
    newEncryptionKey: ArrayBuffer
): Promise<void> {
    const res = await fetch(`${API}/vault`, { credentials: "include" });
    if (!res.ok) throw new Error("Failed to fetch vault entries");
    const entries: Array<{ id: number; account: string; password: string; iv: string; salt: string }> = await res.json();

    const oldKeyBytes = Uint8Array.from(
        oldEncryptionKeyHex.match(/.{2}/g)!.map(b => parseInt(b, 16))
    );
    const oldKey = await crypto.subtle.importKey("raw", oldKeyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    const newKey = await crypto.subtle.importKey("raw", newEncryptionKey, { name: "AES-GCM" }, false, ["encrypt"]);

    for (const entry of entries) {
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: base64ToBuffer(entry.iv) },
            oldKey,
            base64ToBuffer(entry.password)
        );

        const newIv = crypto.getRandomValues(new Uint8Array(12));
        const newSalt = crypto.getRandomValues(new Uint8Array(16));
        const reencrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: newIv },
            newKey,
            decrypted
        );

        const putRes = await fetch(`${API}/vault/entry/${entry.id}`, {
            method: "PUT",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                account: entry.account,
                password: bufferToBase64(reencrypted),
                iv: bufferToBase64(newIv.buffer),
                salt: bufferToBase64(newSalt.buffer),
            }),
        });

        if (!putRes.ok) throw new Error(`Failed to re-encrypt entry ${entry.id}`);
    }
}

function UserMenu() {
    const navigate = useNavigate();
    const username = sessionStorage.getItem("username") ?? "user";

    // Change password state
    const [currentPassword, setCurrentPassword] = useState("");
    const [newPassword, setNewPassword] = useState("");
    const [newPassword2, setNewPassword2] = useState("");
    const [changeMsg, setChangeMsg] = useState("");
    const [changeSuccess, setChangeSuccess] = useState(false);
    const [showChangeForm, setShowChangeForm] = useState(false);
    const [changeLoading, setChangeLoading] = useState(false);

    // Delete account state
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [deletePassword, setDeletePassword] = useState("");
    const [deleteMsg, setDeleteMsg] = useState("");
    const [deleteLoading, setDeleteLoading] = useState(false);

    function getSessionOrRedirect() {
        const encryptionKey = sessionStorage.getItem("encryptionKey");
        const userId = sessionStorage.getItem("userId");
        const email = sessionStorage.getItem("email");
        if (!encryptionKey || !userId || !email) { navigate("/"); return null; }
        return { encryptionKey, userId, email };
    }

    async function changePasswordSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        setChangeMsg(""); setChangeSuccess(false);

        const session = getSessionOrRedirect();
        if (!session) return;

        if (!currentPassword) { setChangeMsg("Please enter your current password."); return; }
        if (passwordFormatErr(newPassword) !== 0b11111) { setChangeMsg("New password does not meet requirements."); return; }
        if (newPassword !== newPassword2) { setChangeMsg("Passwords do not match."); return; }

        setChangeLoading(true);
        try {
            const saltRes = await fetch(`${API}/auth/get-salt?email=${encodeURIComponent(session.email)}`);
            if (!saltRes.ok) throw new Error("Failed to fetch current salt");
            const { salt: currentSaltHex } = await saltRes.json();
            const currentSalt = hexToBuffer(currentSaltHex);

            const { authKey: currentAuthKey } = await deriveMasterKeys(currentPassword, currentSalt);

            const newSalt = generateRandomSalt();
            const { authKey: newAuthKey, encryptionKey: newEncryptionKey } = await deriveMasterKeys(newPassword, newSalt);

            await reEncryptAllEntries(session.encryptionKey, newEncryptionKey);

            const changeRes = await fetch(`${API}/auth/change-password`, {
                method: "PUT",
                credentials: "include",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    current_hashed_password: bufferToHex(currentAuthKey),
                    new_hashed_password: bufferToHex(newAuthKey),
                    new_salt: bufferToHex(newSalt.buffer as ArrayBuffer),
                }),
            });

            if (changeRes.status === 401) { setChangeMsg("Current password is incorrect."); return; }
            if (!changeRes.ok) { setChangeMsg("Failed to update password. Please try again."); return; }

            sessionStorage.setItem("encryptionKey", bufferToHex(newEncryptionKey));

            setChangeSuccess(true);
            setChangeMsg("Password updated successfully.");
            setCurrentPassword(""); setNewPassword(""); setNewPassword2("");
            setShowChangeForm(false);

        } catch (err) {
            console.error("Change password error:", err);
            setChangeMsg("Something went wrong. Please try again.");
        } finally {
            setChangeLoading(false);
        }
    }

    async function handleDeleteAccount(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        setDeleteMsg("");

        const session = getSessionOrRedirect();
        if (!session) return;

        if (!deletePassword) { setDeleteMsg("Please enter your password."); return; }

        setDeleteLoading(true);
        try {
            const saltRes = await fetch(`${API}/auth/get-salt?email=${encodeURIComponent(session.email)}`);
            if (!saltRes.ok) throw new Error("Failed to fetch salt");
            const { salt: saltHex } = await saltRes.json();

            const { authKey } = await deriveMasterKeys(deletePassword, hexToBuffer(saltHex));

            const res = await fetch(`${API}/auth/account`, {
                method: "DELETE",
                credentials: "include",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ current_hashed_password: bufferToHex(authKey) }),
            });

            if (res.status === 401) { setDeleteMsg("Incorrect password."); return; }
            if (!res.ok) { setDeleteMsg("Failed to delete account. Please try again."); return; }

            sessionStorage.clear();
            navigate("/");

        } catch (err) {
            console.error("Delete account error:", err);
            setDeleteMsg("Something went wrong. Please try again.");
        } finally {
            setDeleteLoading(false);
        }
    }

    async function handleLogout() {
        try { await fetch(`${API}/auth/logout`, { method: "POST", credentials: "include" }); } catch {}
        sessionStorage.clear();
        navigate("/");
    }

    function closeDeleteModal() {
        setShowDeleteModal(false);
        setDeletePassword("");
        setDeleteMsg("");
    }

    return (
        <div className="page">
            <div className="topbar">
                <span className="topbar-logo">pw<span>vault</span></span>
                <div className="topbar-actions">
                    <button className="btn-ghost" onClick={handleLogout}>Sign out</button>
                </div>
            </div>

            <div className="dashboard-layout">
                <div className="welcome-badge">Signed in as <span>{username}</span></div>

                {/* Main action grid */}
                <div className="menu-grid">
                    <div className="menu-card" onClick={() => navigate("/PasswordList")} role="button" tabIndex={0}>
                        <div className="menu-card-icon">🔐</div>
                        <div className="menu-card-title">View Passwords</div>
                        <div className="menu-card-desc">Browse and reveal your stored credentials</div>
                    </div>
                    <div className="menu-card" onClick={() => navigate("/AddPassword")} role="button" tabIndex={0}>
                        <div className="menu-card-icon">＋</div>
                        <div className="menu-card-title">Add Password</div>
                        <div className="menu-card-desc">Encrypt and store a new credential</div>
                    </div>
                </div>

                {/* Change password section */}
                <div className="card card-wide" style={{ marginTop: 8 }}>
                    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                        <div>
                            <div className="card-title" style={{ fontSize: 15 }}>Change Master Password</div>
                            <div className="card-subtitle" style={{ marginBottom: 0 }}>RE-ENCRYPTS ALL VAULT ENTRIES</div>
                        </div>
                        <button className="btn-ghost" onClick={() => {
                            setShowChangeForm(v => !v);
                            setChangeMsg(""); setChangeSuccess(false);
                            setCurrentPassword(""); setNewPassword(""); setNewPassword2("");
                        }}>
                            {showChangeForm ? "Cancel" : "Change"}
                        </button>
                    </div>

                    {showChangeForm && (
                        <form onSubmit={changePasswordSubmit} style={{ display:"flex", flexDirection:"column", gap:0, maxWidth:"none", width:"100%", alignSelf:"unset", marginTop: 20 }}>
                            <div className="field">
                                <label htmlFor="current-password">Current Password</label>
                                <input type="password" id="current-password" value={currentPassword} onChange={e => setCurrentPassword(e.target.value)} placeholder="••••••••••••" />
                            </div>
                            <div className="field">
                                <label htmlFor="new-password">New Password</label>
                                <input type="password" id="new-password" value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder="••••••••••••" />
                            </div>
                            <div className="field">
                                <label htmlFor="new-password2">Confirm New Password</label>
                                <input type="password" id="new-password2" value={newPassword2} onChange={e => setNewPassword2(e.target.value)} placeholder="••••••••••••" />
                            </div>
                            {newPassword && <ul className="validation-list">{passwordFormatMsg(newPassword)}</ul>}
                            {newPassword2 && newPassword !== newPassword2 && (
                                <div className="msg msg-error" style={{ marginTop: 8 }}>{passwordMatchMsg(newPassword, newPassword2)}</div>
                            )}
                            {changeMsg && <div className={`msg ${changeSuccess ? "msg-success" : "msg-error"}`}>{changeMsg}</div>}
                            <button type="submit" className="btn-primary" style={{ marginTop: 16 }} disabled={changeLoading}>
                                {changeLoading ? "Re-encrypting vault…" : "Update Password"}
                            </button>
                        </form>
                    )}
                </div>

                {/* Danger zone */}
                <div className="card card-wide" style={{ marginTop: 8 }}>
                    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                        <div>
                            <div className="card-title" style={{ fontSize: 15 }}>Delete Account</div>
                            <div className="card-subtitle" style={{ marginBottom: 0 }}>PERMANENTLY REMOVES ALL DATA</div>
                        </div>
                        <button className="btn-danger" onClick={() => setShowDeleteModal(true)}>Delete</button>
                    </div>
                </div>
            </div>

            {/* Delete account modal */}
            {showDeleteModal && (
                <div style={{
                    position: "fixed", inset: 0,
                    background: "rgba(0,0,0,0.7)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    zIndex: 100,
                }}>
                    <div className="card" style={{ maxWidth: 400, width: "90%", animation: "fadeUp 0.2s ease both" }}>
                        <div style={{ fontSize: 20, marginBottom: 8 }}>⚠️</div>
                        <div className="card-title" style={{ color: "var(--red)" }}>WARNING</div>
                        <div className="card-subtitle" style={{ marginBottom: 16 }}>THIS ACTION CANNOT BE UNDONE</div>
                        <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 20, lineHeight: 1.6 }}>
                            All credentials stored in your vault will be permanently deleted.
                            Enter your master password to confirm.
                        </p>

                        <form onSubmit={handleDeleteAccount} style={{ display:"flex", flexDirection:"column", gap:0, maxWidth:"none", width:"100%", alignSelf:"unset" }}>
                            <div className="field">
                                <label htmlFor="delete-password">Master Password</label>
                                <input
                                    type="password"
                                    id="delete-password"
                                    value={deletePassword}
                                    onChange={e => setDeletePassword(e.target.value)}
                                    placeholder="••••••••••••"
                                    autoFocus
                                />
                            </div>
                            {deleteMsg && <div className="msg msg-error" style={{ marginTop: 8 }}>{deleteMsg}</div>}
                            <button type="submit" className="btn-primary" style={{ marginTop: 16, background: "var(--red)", borderColor: "var(--red)" }} disabled={deleteLoading}>
                                {deleteLoading ? "Deleting…" : "Permanently Delete Account"}
                            </button>
                            <button type="button" className="btn-ghost" style={{ marginTop: 8, width: "100%", textAlign: "center" }} onClick={closeDeleteModal}>
                                Cancel
                            </button>
                        </form>
                    </div>
                </div>
            )}

            <footer><p>© Password Vault 2026</p></footer>
        </div>
    );
}

export default UserMenu;