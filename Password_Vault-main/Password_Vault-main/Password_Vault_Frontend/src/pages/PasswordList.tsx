import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "./sheets.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface VaultEntry {
    id: number;
    account: string;
    password: string; // base64 ciphertext
    iv: string;       // base64 IV
    salt: string;     // base64 salt (kept for future per-entry HKDF)
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

function base64ToBuffer(b64: string): ArrayBuffer {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

async function decryptPassword(
    ciphertextB64: string,
    ivB64: string,
    encryptionKeyHex: string
): Promise<string> {
    const keyBytes = Uint8Array.from(
        encryptionKeyHex.match(/.{2}/g)!.map(b => parseInt(b, 16))
    );
    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64ToBuffer(ivB64) },
        key,
        base64ToBuffer(ciphertextB64)
    );
    return new TextDecoder().decode(plaintext);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function PasswordList() {
    const navigate = useNavigate();

    const [entries, setEntries] = useState<VaultEntry[]>([]);
    const [revealed, setRevealed] = useState<Record<number, string>>({});
    const [loadError, setLoadError] = useState("");
    const [decryptError, setDecryptError] = useState<Record<number, string>>({});

    // -------------------------------------------------------------------------
    // Fetch vault entries on mount
    // -------------------------------------------------------------------------

    useEffect(() => {
        const encryptionKey = sessionStorage.getItem("encryptionKey");
        const userId = sessionStorage.getItem("userId");

        if (!encryptionKey || !userId) {
            navigate("/");
            return;
        }

        const fetchEntries = async () => {
            try {
                const response = await fetch("http://localhost:8000/vault", {
                    credentials: "include",
                });

                if (response.status === 401) {
                    // Session expired server-side — boot to login
                    sessionStorage.removeItem("encryptionKey");
                    sessionStorage.removeItem("userId");
                    navigate("/");
                    return;
                }

                if (!response.ok) {
                    setLoadError("Failed to load passwords. Please try again.");
                    return;
                }

                const data: VaultEntry[] = await response.json();
                setEntries(data);

            } catch (err) {
                setLoadError("Network error. Please check your connection.");
            }
        };

        fetchEntries();
    }, [navigate]);

    // -------------------------------------------------------------------------
    // Reveal / hide a single entry's password
    // -------------------------------------------------------------------------

    async function toggleReveal(entry: VaultEntry) {
        // If already revealed, hide it
        if (revealed[entry.id] !== undefined) {
            setRevealed(prev => {
                const next = { ...prev };
                delete next[entry.id];
                return next;
            });
            return;
        }

        const encryptionKey = sessionStorage.getItem("encryptionKey");
        if (!encryptionKey) {
            navigate("/");
            return;
        }

        try {
            const plaintext = await decryptPassword(entry.password, entry.iv, encryptionKey);
            setRevealed(prev => ({ ...prev, [entry.id]: plaintext }));
            setDecryptError(prev => {
                const next = { ...prev };
                delete next[entry.id];
                return next;
            });
        } catch {
            setDecryptError(prev => ({
                ...prev,
                [entry.id]: "Could not decrypt — session key may not match.",
            }));
        }
    }

    // -------------------------------------------------------------------------
    // Delete an entry
    // -------------------------------------------------------------------------

    async function deleteEntry(entryId: number) {
        try {
            const response = await fetch(`http://localhost:8000/vault/entry/${entryId}`, {
                method: "DELETE",
                credentials: "include",
            });

            if (!response.ok) {
                setLoadError("Failed to delete entry.");
                return;
            }

            setEntries(prev => prev.filter(e => e.id !== entryId));
            setRevealed(prev => {
                const next = { ...prev };
                delete next[entryId];
                return next;
            });

        } catch {
            setLoadError("Network error while deleting.");
        }
    }

    // -------------------------------------------------------------------------
    // Render
    // -------------------------------------------------------------------------

    return (
        <div>
            <header></header>

            <section>
                <h1>Your Passwords</h1>
                <button type="button" onClick={() => navigate("/UserMenu")}>← Back</button>
                <br /><br />

                {loadError && <p style={{ color: "red" }}>{loadError}</p>}

                {entries.length === 0 && !loadError && (
                    <p>No saved passwords yet.</p>
                )}
                <div style={{ height:'300px', overflowY: 'auto', border: '1px solid #ccc', padding: '10px'}}>
                    <ul style={{ listStyle: "none", padding: 0 }}>
                        {entries.map(entry => (
                            <li key={entry.id} style={{ marginBottom: "1rem" }}>
                                <strong>{entry.account}</strong>
                                <br />
                                {revealed[entry.id] !== undefined ? (
                                    <span>{revealed[entry.id]}</span>
                                ) : (
                                    <span>••••••••</span>
                                )}
                                {decryptError[entry.id] && (
                                    <span style={{ color: "red" }}> {decryptError[entry.id]}</span>
                                )}
                                <br />
                                <button
                                    type="button"
                                    onClick={() => toggleReveal(entry)}
                                >
                                    {revealed[entry.id] !== undefined ? "Hide" : "Reveal"}
                                </button>
                                {" "}
                                <button
                                    type="button"
                                    onClick={() => deleteEntry(entry.id)}
                                >
                                    Delete
                                </button>
                            </li>
                        ))}
                    </ul>
            </div>
            </section>

            <footer>
                <p>© Password Vault 2026</p>
            </footer>
        </div>
    );
}

export default PasswordList;
