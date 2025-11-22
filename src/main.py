# src/main.py
import tkinter as tk
from tkinter import messagebox
from src.detector import analyze_url
from src.report import save_report


def show_reasons(reasons):
    """Display all reasons for marking a URL as unsafe."""
    reason_text = "\n".join([f"- {r}" for r in reasons])
    messagebox.showwarning("Reasons", f"Reasons for detection:\n{reason_text}")


def check_url():
    """Main logic for checking the entered URL."""
    url = entry.get().strip()

    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return

    result_label.config(text="Checking...", fg="black")
    root.update_idletasks()

    try:
        # Use unified analyzer (ML + Rule)
        analysis = analyze_url(url)

        verdict = analysis.get("final_verdict", "unknown").lower()
        reasons = analysis.get("reasons", [])
        score = analysis.get("final_score", 0)

        # Decide label colors and messages
        if "phishing" in verdict:
            result_label.config(text=f"❌ PHISHING (Score: {score:.1f})", fg="red")
            reason_button.config(state="normal")
        elif "suspicious" in verdict:
            result_label.config(text=f"⚠️ SUSPICIOUS (Score: {score:.1f})", fg="orange")
            reason_button.config(state="normal")
        else:
            result_label.config(text=f"✅ SAFE (Score: {score:.1f})", fg="green")
            reason_button.config(state="disabled")

        reason_button.reasons = reasons

        # Save report to file
        save_report(url, verdict.upper(), "; ".join(reasons))

    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze URL:\n{str(e)}")


# GUI Setup
root = tk.Tk()
root.title("Phishing URL Detector (ML + Rule Engine)")
root.geometry("480x320")

label = tk.Label(root, text="Enter URL to check:", font=("Arial", 12))
label.pack(pady=10)

entry = tk.Entry(root, width=50)
entry.pack(pady=5)

check_button = tk.Button(root, text="Check URL", command=check_url, bg="blue", fg="white")
check_button.pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack(pady=10)

reason_button = tk.Button(
    root,
    text="Show Reason",
    command=lambda: show_reasons(reason_button.reasons),
    state="disabled",
    bg="orange"
)
reason_button.pack(pady=10)

root.mainloop()
