# lytter - network scanner (i fucking hate this project)


## overview

this *thing* is supposed to scan your fucking network and find devices. maybe it will, maybe it won’t. i’ve poured, i don’t even know, hundreds of hours into this fucking bullshit and it’s somehow still not stable. if it decides to work, great. if not? don’t ask me why, because i don't know. it’s here, it does a thing, sometimes, and that's all you get.

## features

- tui looks clean tho
- scans your network for devices. might detect them. might not. 
- displays ips and macs. sometimes. if the ui isn’t stuck in purgatory. 
- tracks devices, but i wouldn’t bet on it actually showing you all the devices.
- whitelists devices you don't wanna scan
  
## installation

1. clone this damn thing.
2. install the fucking dependencies:
    ```bash
    pip install -r requirements.tst
    ```
3. pray your system can even handle sniffing packets. 

## how to run

```bash
python lytter.py
```

it’ll start scanning your network. maybe you’ll see devices. maybe you won’t. it might even work for a minute, and then just randomly stop. don’t ask me why, i’ve given up.
ui should refresh every second but what if it doesn’t? dunno, i just restart it and that's it.

## configuration

1. got a `config.toml` file? sure. you can whitelist devices. 
2. device history is saved in `device_history.json`. this file is more reliable than fucking tui.

## known issues

- the tui? it might update, it might not. sometimes it freezes.
- devices *might* show up. or maybe they’ll be invisible. `device_history.json` is better way to see devices lol.
- the whole fucking thing might just crash randomly because i’ve forgotten to handle some edge case that doesn’t even matter anymore. 
- if you get an error? just restart it. maybe it’ll work next time. maybe it won’t.
- i’m exhausted. i don’t care. you’re on your own.

## license
this is open-source, so you can do whatever you want with it. fork it, break it, delete it. at this point, i don’t give a single shit.
