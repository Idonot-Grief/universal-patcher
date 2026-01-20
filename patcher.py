import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import shutil
import tempfile
import json
import zlib
import struct

MAGIC = b'PDAT'

class UniversalPatcherApp:
    def __init__(self, root):
        self.root = root
        root.title("Universal Patcher")
        root.geometry("900x600")
        self.show_main_menu()

    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    # =========================
    # MAIN MENU
    # =========================
    def show_main_menu(self):
        self.clear()
        tk.Label(
            self.root, text="Universal Patcher", font=("Segoe UI", 20, "bold")
        ).pack(pady=20)

        tk.Button(
            self.root, text="JSON Text Patch Mode", height=2, width=35, command=self.show_json_mode
        ).pack(pady=10)

        tk.Button(
            self.root, text="Offset Patch Mode (.pdata)", height=2, width=35, command=self.show_offset_menu
        ).pack(pady=10)

    # =========================
    # JSON PATCH MODE
    # =========================
    def show_json_mode(self):
        self.clear()
        self.backup_var = tk.BooleanVar(value=True)

        tk.Label(self.root, text="Patch JSON").pack(anchor="w", padx=5)
        self.json_box = scrolledtext.ScrolledText(self.root, height=18)
        self.json_box.pack(fill="both", expand=True, padx=5, pady=5)

        opts = tk.Frame(self.root)
        opts.pack(fill="x")
        tk.Checkbutton(opts, text="Create .bak backups", variable=self.backup_var).pack(side="left")

        btns = tk.Frame(self.root)
        btns.pack(fill="x", pady=5)

        tk.Button(btns, text="Back to Main Menu", command=self.show_main_menu).pack(side="left", padx=5)
        tk.Button(btns, text="Load JSON File", command=self.load_json).pack(side="left", padx=5)
        tk.Button(btns, text="Patch Files", command=self.patch_files).pack(side="right", padx=5)

    def load_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            self.json_box.delete("1.0", tk.END)
            self.json_box.insert(tk.END, f.read())

    def patch_files(self):
        try:
            patch_data = json.loads(self.json_box.get("1.0", tk.END))
        except Exception as e:
            messagebox.showerror("JSON Error", str(e))
            return

        files = filedialog.askopenfilenames(title="Select files to patch")
        if not files:
            return

        ops = patch_data.get("operations", [])
        do_backup = patch_data.get("backup", self.backup_var.get())
        errors = []

        for path in files:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()

                original = content

                for op in ops:
                    t = op["type"]
                    if t == "replace":
                        content = content.replace(op["find"], op["replace"])
                    elif t == "remove":
                        content = content.replace(op["find"], "")
                    elif t == "insert_before":
                        content = content.replace(op["find"], op["insert"] + op["find"])
                    elif t == "insert_after":
                        content = content.replace(op["find"], op["find"] + op["insert"])
                    elif t == "append":
                        content += op["text"]
                    elif t == "prepend":
                        content = op["text"] + content
                    else:
                        raise ValueError(f"Unknown operation: {t}")

                if content != original:
                    if do_backup:
                        shutil.copy2(path, path + ".bak")

                    fd, tmp = tempfile.mkstemp(text=True)
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.write(content)
                    os.replace(tmp, path)

            except Exception as e:
                errors.append(f"{path}: {e}")

        if errors:
            messagebox.showerror("Errors", "\n".join(errors))
        else:
            messagebox.showinfo("Success", "Files patched successfully.")

    # =========================
    # OFFSET PATCH MENU
    # =========================
    def show_offset_menu(self):
        self.clear()
        tk.Label(self.root, text="Offset Patch Mode", font=("Segoe UI", 16, "bold")).pack(pady=10)

        tk.Button(self.root, text="Patch File Using .pdata", height=2, width=35, command=self.show_apply_patch).pack(pady=10)
        tk.Button(self.root, text="Create .pdata Patch", height=2, width=35, command=self.show_create_patch).pack(pady=10)
        tk.Button(self.root, text="Back to Main Menu", command=self.show_main_menu).pack(pady=20)

    # =========================
    # APPLY PATCH
    # =========================
    def show_apply_patch(self):
        self.clear()
        tk.Label(self.root, text="Apply .pdata Patch", font=("Segoe UI", 14)).pack(pady=10)

        self.original_file = tk.StringVar()
        self.patch_file = tk.StringVar()

        self.file_picker("Original File", self.original_file)
        self.file_picker("Patch File (.pdata)", self.patch_file)

        tk.Button(self.root, text="Patch File", command=self.apply_pdata).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_offset_menu).pack(pady=5)

    def apply_pdata(self):
        try:
            with open(self.patch_file.get(), "rb") as f:
                data = f.read()

            if data[:4] != MAGIC:
                raise ValueError("Invalid .pdata file")

            ext_len = data[4]
            ext = data[5:5+ext_len].decode('ascii')
            orig_size = struct.unpack(">Q", data[5+ext_len:13+ext_len])[0]
            compressed = data[13+ext_len:]
            patch_bytes = zlib.decompress(compressed)

            if not self.original_file.get().endswith(ext):
                raise ValueError("File extension mismatch")

            with open(self.original_file.get(), "rb") as f:
                content = bytearray(f.read())

            i = 0
            while i < len(patch_bytes):
                offset = struct.unpack(">Q", patch_bytes[i:i+8])[0]
                i += 8
                run_len = struct.unpack(">I", patch_bytes[i:i+4])[0]
                i += 4
                run = patch_bytes[i:i+run_len]
                i += run_len
                if offset + len(run) > len(content):
                    content.extend(b'\x00' * (offset + len(run) - len(content)))
                content[offset:offset+len(run)] = run

            base, ext2 = os.path.splitext(self.original_file.get())
            out_path = base + "-patched" + ext2
            with open(out_path, "wb") as f:
                f.write(content)

            messagebox.showinfo("Success", f"Patched file created: {out_path}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    # =========================
    # CREATE PATCH
    # =========================
    def show_create_patch(self):
        self.clear()
        tk.Label(self.root, text="Create .pdata Patch", font=("Segoe UI", 14)).pack(pady=10)

        self.orig_file = tk.StringVar()
        self.mod_file = tk.StringVar()
        self.save_patch = tk.StringVar()

        self.file_picker("Original File", self.orig_file)
        self.file_picker("Modified File", self.mod_file)
        self.save_picker("Save .pdata As", self.save_patch)

        tk.Button(self.root, text="Create Patch", command=self.create_pdata).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_offset_menu).pack(pady=5)

    def create_pdata(self):
        try:
            orig_path = self.orig_file.get()
            mod_path = self.mod_file.get()
            save_path = self.save_patch.get()

            if os.path.splitext(orig_path)[1] != os.path.splitext(mod_path)[1]:
                raise ValueError("Files must have the same extension")

            with open(orig_path, "rb") as f:
                orig = f.read()
            with open(mod_path, "rb") as f:
                mod = f.read()

            # Multi-byte runs
            patches = []
            i = 0
            while i < min(len(orig), len(mod)):
                if orig[i] != mod[i]:
                    start = i
                    run = bytearray()
                    while i < len(mod) and (i - start) < 2**32 and (i >= len(orig) or orig[i] != mod[i]):
                        run.append(mod[i])
                        i += 1
                    patches.append((start, run))
                else:
                    i += 1
            # Extra bytes
            if len(mod) > len(orig):
                patches.append((len(orig), mod[len(orig):]))

            # Serialize header
            data = bytearray()
            ext_bytes = os.path.splitext(orig_path)[1].encode('ascii')
            data += MAGIC
            data += struct.pack("B", len(ext_bytes))
            data += ext_bytes
            data += struct.pack(">Q", len(orig))  # original size

            # Serialize patch runs
            patch_bytes = bytearray()
            for offset, run in patches:
                patch_bytes += struct.pack(">Q", offset)
                patch_bytes += struct.pack(">I", len(run))
                patch_bytes += run

            data += zlib.compress(patch_bytes)

            with open(save_path, "wb") as f:
                f.write(data)

            messagebox.showinfo("Success", f"Patch created: {save_path}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    # =========================
    # FILE PICKERS
    # =========================
    def file_picker(self, label, var):
        frame = tk.Frame(self.root)
        frame.pack(fill="x", padx=10, pady=5)
        tk.Label(frame, text=label, width=25, anchor="w").pack(side="left")
        tk.Entry(frame, textvariable=var).pack(side="left", fill="x", expand=True)
        tk.Button(frame, text="Browse", command=lambda: var.set(filedialog.askopenfilename())).pack(side="left")

    def save_picker(self, label, var, ext=".pdata"):
        frame = tk.Frame(self.root)
        frame.pack(fill="x", padx=10, pady=5)
        tk.Label(frame, text=label, width=25, anchor="w").pack(side="left")
        tk.Entry(frame, textvariable=var).pack(side="left", fill="x", expand=True)
        tk.Button(frame, text="Browse", command=lambda: var.set(filedialog.asksaveasfilename(defaultextension=ext))).pack(side="left")


if __name__ == "__main__":
    root = tk.Tk()
    UniversalPatcherApp(root)
    root.mainloop()
