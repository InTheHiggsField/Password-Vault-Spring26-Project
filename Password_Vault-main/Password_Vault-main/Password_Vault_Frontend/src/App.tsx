import React from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import AddPassword from "./pages/AddPassword";
import LoginPage from "./pages/LoginPage";
import NewAccount from "./pages/NewAccount";
import PasswordList from "./pages/PasswordList";
import UserMenu from "./pages/UserMenu";

// ---------------------------------------------------------------------------
// Route guard — boots unauthenticated users back to login
// ---------------------------------------------------------------------------

function ProtectedRoute({ children }: { children: React.ReactNode }) {
    const encryptionKey = sessionStorage.getItem("encryptionKey");
    const userId = sessionStorage.getItem("userId");

    if (!encryptionKey || !userId) {
        return <Navigate to="/" replace />;
    }

    return <>{children}</>;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export default function App() {
    return (
        <BrowserRouter>
            <Routes>
                <Route path="/" element={<LoginPage />} />
                <Route path="/NewAccount" element={<NewAccount />} />
                <Route path="/UserMenu" element={
                    <ProtectedRoute>
                        <UserMenu />
                    </ProtectedRoute>
                } />
                <Route path="/PasswordList" element={
                    <ProtectedRoute>
                        <PasswordList />
                    </ProtectedRoute>
                } />
                <Route path="/AddPassword" element={
                    <ProtectedRoute>
                        <AddPassword />
                    </ProtectedRoute>
                } />
            </Routes>
        </BrowserRouter>
    );
}

// ---------------------------------------------------------------------------
// Shared password validation helpers (used by NewAccount, UserMenu)
// ---------------------------------------------------------------------------

export function passwordMatchMsg(password: string, password2: string) {
    if (password2 !== password) {
        return "Passwords MUST match";
    }
}

export function passwordFormatErr(password: string): number {
    /* Bitwise error code — format (00000):
     *   bit 0 (0b00001): length >= 8
     *   bit 1 (0b00010): contains digit [0-9]
     *   bit 2 (0b00100): contains uppercase [A-Z]
     *   bit 3 (0b01000): contains special character
     *   bit 4 (0b10000): no invalid characters (non-printable / non-ASCII)
     *
     * All bits set (0b11111) means no errors.
     */
    let err_num = 0b10000; // assume no invalid chars until proven otherwise

    if (password.length >= 8) {
        err_num |= 0b00001;
    }

    for (let i = 0; i < password.length; i++) {
        const c = password.charCodeAt(i);

        if (47 < c && c < 58) {
            err_num |= 0b00010; // digit
        }
        if (64 < c && c < 91) {
            err_num |= 0b00100; // uppercase
        }
        if ((32 < c && c < 48) || (57 < c && c < 65) || (90 < c && c < 97) || (122 < c && c < 127)) {
            err_num |= 0b01000; // special character
        }
        if (c <= 32 || c > 127) {
            err_num &= 0b01111; // invalid character found — clear bit 4
        }
    }

    return err_num;
}

export function passwordFormatMsg(password: string): React.ReactElement[] {
    const msgs: string[] = [];
    const err_num = passwordFormatErr(password);

    if ((err_num & 0b00001) === 0) msgs.push("Password must be at least 8 characters long.");
    if ((err_num & 0b00010) === 0) msgs.push("Password must contain at least 1 digit [0-9].");
    if ((err_num & 0b00100) === 0) msgs.push("Password must contain at least 1 uppercase letter [A-Z].");
    if ((err_num & 0b01000) === 0) msgs.push("Password must contain at least 1 special character (&%*^ etc.).");
    if ((err_num & 0b10000) === 0) msgs.push("Password contains an invalid character.");

    return msgs.map((msg, i) => <li key={i}>{msg}</li>);
}
