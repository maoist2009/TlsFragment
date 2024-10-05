# About

According to [gfw_knocker](https://github.com/gfw-knocker/) fragment the ClinetHello may bypass the gfw.

But it seems that it doesn't work in Shanghai.

# Usage

All the config is in `config.json`.

## Domain match

We use an AC automaton to match the domains.

We map the **longest** domain setting for the sni. If multiple, randomly choose one of **the longests**. (You'll see the code, it determines the python `sorted` function).
