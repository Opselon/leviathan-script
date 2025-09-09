

Leviathan is a powerful, menu-driven Bash script designed for system administrators, DevOps engineers, and Linux power users. It consolidates hundreds of commands into a single, intelligent framework, automating complex tasks from security hardening to performance tuning.

This version introduces a new philosophy: **"Self Health and More Futures"**, integrating tools not just for the machine's well-being, but for the operator's focus and productivity, alongside features for planning and future-proofing your system.

## ✨ Key Features

| Feature                          | Description                                                                                             | Icon |
| -------------------------------- | ------------------------------------------------------------------------------------------------------- | :--: |
| **Intelligent System Updates**   | One-command `update`, `upgrade`, `dist-upgrade`, `autoremove`, and `clean` sequence.                    |  🚀  |
| **Advanced Performance Tuning**  | Interactively tweak CPU governors, memory swappiness, and enable modern protocols like **TCP BBR**.     |  ⚡️  |
| **Comprehensive Security Suite** | Harden SSH, configure firewalls with UFW, deploy Fail2Ban, and run full system audits with Lynis.       |  🛡️  |
| **Health & Futures Planning**    | Monitor system vitals, use focus tools, and forecast disk usage to stay ahead of problems.              | ❤️‍🩹 |
| **Automated Reporting**          | Generate a detailed **HTML report** with system summary, disk/memory usage, and security audit findings. |  📊  |
| **Interactive Dependency Mgmt**  | Smartly detects and interactively prompts for the installation of any missing tools.                    |  🧩  |
| **Seamless Self-Update**         | Checks for new versions on GitHub and allows for a simple, in-place update.                             |  ⬆️  |

---

## 🚀 Getting Started

Getting Leviathan up and running is a simple two-step process.

### Step 1: Installation
Run the following command in your terminal. This will download the latest version of Leviathan, place it in `/usr/local/bin`, and make it executable.

```bash
sudo curl -sSL https://raw.githubusercontent.com/Opselon/leviathan-script/main/Leviathan.sh -o /usr/local/bin/leviathan && sudo chmod +x /usr/local/bin/leviathan && sudo bash /usr/local/bin/leviathan
```



> **💡 Pro Tip:** For easier access, create an alias in your shell's configuration file (`~/.bashrc` or `~/.zshrc`):
> ```bash
> alias leviathan='sudo bash /usr/local/bin/leviathan'
> ```
> After adding the alias, reload your shell (`source ~/.bashrc`) and you can simply type `leviathan` to start the script.

---

## ⚙️ Dependencies

Leviathan is designed for **Debian-based systems** (e.g., Ubuntu, Kali Linux) and uses `apt` for package management.

The script has a built-in interactive dependency checker. When you first run it, it will find any missing tools and provide a user-friendly menu to manage their installation:
- **Install All:** Automatically install all missing dependencies.
- **Choose Packages:** Select specific tools to install from a list.
- **Skip:** Proceed at your own risk (some modules may not function).

---

## ⚠️ Disclaimer

This script performs powerful operations and requires **root privileges**. It makes significant changes to system configuration files.

-   **Always back up your data** before running major operations.
-   Review the source code to understand what each module does before using it.
-   The author is not responsible for any data loss or system damage. **Use at your own risk.**

---

## 🤝 Contributing

Contributions are what make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

Please refer to the `CONTRIBUTING.md` for details on our code of conduct and the process for submitting pull requests.

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

---

<p align="center">Crafted with ❤️ for the Linux community.</p>

```
