# Contributing to decodeX

First off, thank you for considering contributing to **decodeX**! It's people like you that make the open-source community such an amazing place to learn, inspire, and create.

## How Can I Contribute?

### Reporting Bugs
If you find a bug, please open an issue and include:
- A clear description of the problem.
- Steps to reproduce the bug.
- Expected behavior vs. actual behavior.
- Details about your environment (OS, Python version).

### Suggesting Enhancements
We love new ideas! If you have a suggestion for an improvement:
- Check if the idea has already been suggested.
- Open an issue with the "enhancement" tag.
- Explain why this feature would be useful.

### Pull Requests
1. Fork the repo and create your branch from `main`.
2. Ensure your code follows the existing style (clean, modular, documented).
3. If you've added a new plugin, ensure it follows the abstract base class in `framework/plugin_base.py`.
4. Update the documentation if necessary.
5. Submit a pull request!

## Plugin Development
DecodeX is built on a plugin architecture. To create a new plugin:
1. Create a new `.py` file in `decodeX/plugins/`.
2. Inherit from the `Plugin` class.
3. Implement the `execute` method.
4. (Optional) Define YARA rules in `decodeX/rules/` if your plugin uses signature matching.

## Code of Conduct
Please be respectful and professional in all interactions.

---
**Happy Hacking!** 🛡️
