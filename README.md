<<<<<<< HEAD
# Multi-Layer Encrypted Chat System
=======
# Multi-Layer Encrypted Chatting System
>>>>>>> 255ec06e9c8275fd7c27ac1c3155589c060d6378

> **WARNING: This is NOT a production-ready project!**  
> Just a backup of my learning experiments. Use at your own risk!

## What is this mess?

A half-baked, probably broken, multi-layer encrypted communication system I've been tinkering with. It includes:
- A server that kinda works (sometimes)
- A client that connects (most of the time)
- SSL/TLS encryption layer
- Some additional crypto stuff I threw in there because why not

## BIG FAT DISCLAIMER

I'm **COMPLETELY NEW** to this stuff. Like, "just learned what SSL stands for yesterday" new. This code is:<br>
Full of bugs (I'm sure)<br>
Probably insecure as hell<br>
Missing half the features I planned<br>
A total mess to look at<br>

**DO NOT** use this for anything serious. I'm literally just keeping it here as a backup before I accidentally rm -rf my entire project folder.

## What's supposed to work?
**done:**<br>
Basic client-server connection <br>
SSL/TLS handshake (I think?) <br>
Some AES encryption on top of SSL (overkill? maybe) <br>
**working in progress:** <br>
Actually secure key exchange (yeah now) <br>
Proper error handling (lol) <br>
Documentation (you're reading it) <br>
Tests (what are those?) <br>

## No Easy Start Guide

Yeah. No `npm install && npm start` here. No fancy setup scripts. No step-by-step tutorials.

If you really want to run this:
1. Figure out how to generate SSL certs yourself (FYI, I pushed the test cert I was using to the repo. Just a self-signed one I found online, so it’s not secure. We can always make a new one, no worries.)
2. Figure out how to install the dependencies
3. Figure out how to actually run the server and client
4. Good luck, you'll need it

## Tech Stack (I think?)

Python (because it's one of the few programming languages I kinda know) <br>
SSL/TLS (copied from internet mostly)<br>
AES encryption (from some tutorial I found)<br>
Sockets (the basic stuff)<br>

## Contributing

Please don't. Seriously. This is my personal learning dumpster fire. But if you really want to point and laugh at my code, feel free to open an issue. I could use a good cry.

## License

MIT? IDK, do whatever you want with this code. Just don't blame me when it breaks or gets hacked.

---

**P.S. If you're reading this, don't judge me too harshly plz. We all start somewhere, right? ...Right?** 😅
