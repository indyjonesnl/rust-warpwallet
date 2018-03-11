# rust-warpwallet
A warpwallet implementation written in noobish rust.

### What is WarpWallet?
> WarpWallet is a deterministic bitcoin address generator. You never have to save or store your private key anywhere. Just pick a really good password - many random words, for example - and never use it for anything else.
>
> WarpWallet adds two improvements: (1) WarpWallet uses scrypt to make address generation both memory and time-intensive. And (2) you can "salt" your passphrase with your email address. Though salting is optional, we recommend it. Any attacker of WarpWallet addresses would have to target you individually, rather than netting you in a wider, generic sweep. And your email is trivial to remember, so why not?

Quote taken from: https://keybase.io/warp

### Why Rust?
[Some smart people](http://www.oreilly.com/programming/free/why-rust.csp) can explain it a lot better than I could.

### Why learn Rust by implementing Warpwallet (or something with crypto)?
Crypto is in my opinion interesting specifically for learning software development because crypto simulates a real-world application.
In school we learned about storing 2 strings in a database and that's about as far as we went into the water.

But with crypto-related topics, you have to think about memory usage (because Scrypt can use a lot of memory), CPU usage (because most hashing functions are not instant) or threading (warpwallet performs 2 crypto algorithms independent of each other, making it the **perfect** candidate, in my opinion).

Honestly, I am personally tired with software development how-to websites that show you how to do threading with _thread.sleep(100);_...

### Some words from the author
This repository is partly me trying to learn rust and partly implementing a fully working [warpwallet](https://keybase.io/warp) in Rust.
Sorry if the code is ugly, I have been experimenting with some threading (without threading libraries), to see if I can get any simple or quick speed optimisations by paralellising processes (I think) could be paralellised. (say that 10 times...)

I would be super happy to get any feedback, I am still learning Rust and every day I find new stuff I did completely wrong yesterday.
So far I am super happy with the current state of Rust, the speed, the toolchain, the iteration speed (though the code hinting is IntelliJ is slow AF) and I foresee great potential with Rust.

Now I just need to learn how to do 'fearless concurrency' in Rust, the way it is supposed to.