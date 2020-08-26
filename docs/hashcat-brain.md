# The hashcat brain

This feature will have a significant impact on the art of password cracking - either cracking alone, in small teams over a local network, or in large teams over the Internet.

From a technical perspective, the hashcat brain consists of two in-memory databases called "long-term" and "short-term". When I realized that the human brain also has such a long-term and a short-term memory, that's when I chose to name this feature the "hashcat brain". No worries, you don't need to understand artificial intelligence (AI) here - we are simply talking about the "memory features" of the human brain.

Put simply, the hashcat brain persistently remembers the attacks you've executed against a particular hashlist in the past ... but on a low level.

Hashcat will check each password candidate against the "brain" to find out if that candidate was already checked in the past and then accept it or reject it. The brain will check each candidate for existence in both the long-term and short-term memory areas. The nice thing is that it does not matter which attack-mode originally was used - it can be straight attack, mask attack or any of the advanced future generators.

The brain computes a hash (a very fast one called xxHash) of every password candidate and store it in the short-term memory first. Hashcat then starts cracking the usual way. Once it's done cracking, it sends a "commit" signal to the hashcat brain, which then moves the candidates from the short-term memory into the long-term memory.

The hashcat brain feature uses a client/server architecture. That means that the hashcat brain itself is actually a network server. I know, I know - you don't want any network sockets in your hashcat process? No problem, then disable the feature in the __makefile__ by setting `ENABLE_BRAIN=0` and it will be gone forever.

It's a network server for a reason. This way we can run multiple hashcat clients ... all using the same hashcat brain. This is great for collaboration with many people involved - plus it stays alive after the client shuts down. (Note, however, that even if you want to only use brain functionality locally, you must run two separate instances of hashcat - one to be the brain server, and one to be the client and perform attacks).

That's it from the technical perspective. It's hard to explain how much potential there is in this, and I'm wondering why I didn't invent this sooner. Maybe it took the Crack Me If You Can password-cracking challenge to realize that we need a feature like this.

## Examples

Before you try it out yourself, let me show you a few examples.

### Example 1: Duplicate candidates all around us

There's no doubt that rule-based attacks are the greatest general purpose attack-modifier on an existing wordlist. But they have a little-known problem: They produce a lot of duplicate candidates. While this is not relevant for fast hashes, it has a large impact on slow hashes.

In this example, we apply best64.rule to example.dict, and writes the result to test.txt:

```
$ ./hashcat --stdout example.dict -r rules/best64.rule -o test.txt
```

Now we can see how many candidates were produced:

```
$ cat test.txt | wc -l
9888032
```

And now, let's see how many unique candidates are inside:

```
$ sort -u test.txt | wc -l
7508620
```

Of course, the wordlist and rules used have a large impact on the number of duplicates. In our example - a common wordlist and general purpose rule - the average ratio of produced dupes seems to be around 25%. And all of these dupes are detected by the brain:

```
$ ./hashcat -z example0.hash example.dict -r rules/best64.rule
...
Rejected.........: 2379391/9888032 (24.06%)
```

> __Notes:__ Hashcat brain rejects dynamically created duplicate candidates
>
> Average dynamically created duplicate candidates is around 25%
>
> Eliminating the duplicate 25% reduces the attack time by 25%

### Example 2: stop caring about what you've done in the past

Think of this: you have a single hash, but it is very high profile. You can use all of your resources. You start cracking - nothing. You try a different attack - still nothing. You're frustrated, but you must continue.. So try more attacks ... but even after two or more days - nothing. You start wondering what you've already done, but you're starting to lose track, getting tired, and making mistakes. Guess what? The hashcat brain comes to the rescue! Here's an attack that you've tried:

```
$ ./hashcat -z -m 6211 hashcat_ripemd160_aes.tc rockyou.txt
...
Time.Started.....: xxx (32 mins, 6 secs)
```

Note that the way you use hashcat doesn't change at all. The hash mode and attack mode can be replaced with anything you'd like. The only difference in your attack is that you add the new `-z` option to enable hashcat's new brain "client" functionality. By using `-z` you will also automatically enable the use of "slow candidates" `-S` mode.

Now let's say that two days later, you forgot that you already performed the attack before. Or maybe it wasn't you who forgot, it's just your coworker on a different machine also trying. This is what happens:

```
$ ./hashcat -z -m 6211 hashcat_ripemd160_aes.tc rockyou.txt
...
Rejected.........: 14344384/14344384 (100.00%)
Time.Started.....: xxx (15 secs)
```

The hashcat brain correctly rejected *all* of the candidates.

> __Important things to note here:__ The rejected count exactly matches the keyspace.
>
> The attack took a bit of time - it's not 0 seconds. The process is not completely without cost. The client must hash all of the candidates, and transfer them to the hashcat brain; the hashcat brain must then search for those candidates in both memory regions, and send back a reject list; and then hashcat must select new candidates to fill the reject gaps, and so on ...
>
> __Most important:__ 15 seconds is less than 32 minutes

### Example 3: It's the candidates that matter, not the attack

As I've stated above, it's not the command line that is stored somehow - it's not high level storage in this mode. This is where the hashcat brain server starts to create a strong advantage over manual (even organized) selection of attacks, because of the overlaps that naturally occur when carrying out a variety of attacks:

```
$ ./hashcat -z -m 6211 hashcat_ripemd160_aes.tc -a 3 ?d?d?d?d
...
Rejected.........: 6359/10000 (63.59%)
```

So what happened here? It rejected 63.59% of a mask? Yes, it did. The reason is this:

```
$ grep -c '^[0123456789]\{4\}$' rockyou.txt
6359
```

> __Notes:__ The previous command from the second example kicks in here. In the rockyou wordlist, we have 6359 pure digits with length 4 and the hashcat brain was able to reject them - because the mask ?d?d?d?d will also produce them The hashcat brain does not care about your attack mode.
>
> Actually, you could say that the hashcat brain creates a kind of dynamic cross attack-mode while you are using it. As you can see here, attack-mode 0 and attack-mode 3 work together.
>
> The hashcat brain does not end after hashcat finishes - it stays intact because it's a stand-alone process

### Example 4: Improve on what you've done in the past

So you're out of ideas, and you start to run some simple brute-force. But you're clever, because you know the target tends to use the symbol "`$`" somewhere inside the password, and you optimize your mask for this. Let's start with an example not using the hashcat brain:

```
$ ./hashcat -m 6211 hashcat_ripemd160_aes.tc -a 3 -1 ?l?d$ ?1?1?1?1?1?1
...
Time.Started.....: xxx (5 hours, 37 mins)
Progress.........: 2565726409/2565726409 (100.00%)
```

Damn - it did not crack. But then your coworker shows up and tells you that he found out that the target isn't just using the "`$`" symbol in his passwords, but also the "`!`" symbol. Damn, this makes your previous run (which took 5.5 hours) completely useless - wasted! You now need even more time for the correct run:

```
$ ./hashcat -m 6211 hashcat_ripemd160_aes.tc -a 3 -1 ?l?d$! ?1?1?1?1?1?1
...
Time.Started.....: xxx (6 hours, 39 mins)
Progress.........: 3010936384/3010936384 (100.00%)
```

Now we do the same again, but with hashcat brain enabled. All of the work of that first command will no longer be wasted. The same commandline history, but this time with hashcat brain enabled, looks like this:

```
$ ./hashcat -z -m 6211 hashcat_ripemd160_aes.tc -a 3 -1 ?l?d$ ?1?1?1?1?1?1
...
Time.Started.....: xxx (5 hours, 37 mins)
```

But now, if we add the "!" character, we see the difference:

```
$ ./hashcat -z -m 6211 hashcat_ripemd160_aes.tc -a 3 -1 ?l?d$! ?1?1?1?1?1?1
...
Time.Started.....: xxx (1 hour, 5 mins)
```

So you can see here how the hashcat brain helps you to reduce the time for the second attack, from ~6 hours to ~1 hour.

### Example 5: The resurrection of the random rules

Random rules and salts? No way! Take a look at this, it's horrible:

```
$ cat wordlist.txt
password
$ ./hashcat wordlist.txt --stdout -g 100000 | sort -u | wc -l
20473
```

What I'm trying to show here is how inefficient the random rules actually are (and always have been). They produce tons of duplicate work.

As you can see from the above example, only 20473 of 100000 tested passwords of the produced random candidates are unique - and the remaining 80% is just wasted time.

I cannot believe that I've never thought about this in detail, but now the hashcat brain brings this to an end:

```
./hashcat -z hashlist.txt wordlist.txt -g 100000
...
Rejected.........: 82093/100000 (82.09%)
```

This alone gives `-g` a new role in password cracking. If you've ever attended a password cracking contest, you know how important it is to find the patterns that were used to generate the password candidates. Because finding new patterns using the combination of random-rules and debug-rules is a very efficient way to find new attack vectors.

For example, __Team Hashcat__ managed to crack 188k/300k of the SSHA hashlist from the __2018 CMIYC contest__ - a strong showing. But with random rules, there's a really good chance that you'll discover what you missed. Here's an example of an attack I ran for only few minutes while writing this document:

```
$ ./hashcat -z -m 111 c0_111.list.txt wordlist.txt -g 100000 --debug-mode 4
...
INFO: Removed 188292 hashes found in potfile.
...
time:Z4 R3:tim2eeee
sexual:Y3 Z5 O35:sexllllll
poodle:Y2 T3 sBh:pooDlele
pass123:C z5:ppppppASS123
pool:y4 Z2 Y1:poolpoollll
profit:o8F ^_:_profit
smashing:Z3:smashingggg
```

These are real passwords that __Team Hashcat__ didn't crack during the contest. What matters here is that you can see hints for possible patterns - which counts much more than just cracking a single password. And if you run the exact same command again, hashcat will generate different rules and you get more cracks, and discover more new patterns. You can do this again and again. We call this technique "raking".

Note: It can occur that a pattern discovered from random rules matches an already known pattern. In such a case, it's a strong sign that this pattern may have been searched already, but has not yet been searched exhaustively. Perhaps a previous attack was stopped too early. But with the hashcat brain, that's no longer important - we can just apply the pattern without any worry about creating double work.

## The costs of hashcat brain

It should now be clear now what the potential is here. There are many other examples where this feature really kicks in, but I'm sure you already have your own ideas.

Of course, the hashcat brain does not come for free - there are limitations. It's important to know some key numbers to decide when to use it (and when not to).

Each password candidate creates a hash of 8 bytes that has to be transferred, looked up and stored in the hashcat brain. This brings us to the first question: What kind of hardware do you need? Fortunately, this is pretty easy to calculate. If you have a server with 64 GB of physical memory, then you can store 8,000,000,000 candidates. I guess that's the typical size of every serious password cracker's wordlist; if you have more, you typically have too much trash in your wordlists. If you have less, then you just haven't been collecting them long enough.

So let's assume a candidate list size of 8,000,000,000. That doesn't sound like too much - especially if you want to work with rules and masks. It should be clear that using the hashcat brain against a raw MD5 is not very efficient. But now things become interesting, because of some unexpected effects that kick in.

Imagine you have a salted MD5 list, let's say VBULL which is a fast hash (not a slow hash) - and you have many of them. In thise case, each of the salts starts to work for us.

Yes, you read that right - the more salts, the better!!

Let's continue with our calculation and our 8,000,000,000 password example. The speed of a typical VBULL on a Vega64 is 2170.6 MH/s. If we have 300,000 salts, the speed drops to 7235 H/s. Now to feed the hashcat brain at a rate of 7235 H/s, it will take you 1,105,736 seconds (or 12 days). That means you can run the hashcat brain for 12 days. It's an OK time I think, though I don't let many attacks run for such a long time. Also, this is an inexpensive server with 64GB physical RAM, and you could simply add more RAM, right? At this point we should also consider using swap memory. I think there's actually room for that - but I leave testing this to our users.

Lookup times are pretty good. The hashcat brain uses two binary trees, which means that the more hashes that are added, the more efficient it becomes. Of course, the lookup times will increase drastically in the first moments, but will stabilize at some point. Note that we typically do not compare just one entry vs. million of entries - we compare hundreds of thousands of entries vs. millions of entries.

## Technical details on the hashcat brain server

* The hashcat brain server saves the long-term memory to disk every 5 minutes automatically
* The server also saves the long-term memory if the hashcat brain server is killed using `[Ctrl + C]`
* There's no mitigation against database poisoning - this would cost too many resources
* There's currently no mitigation against an evil client requesting the server to allocate too much memory
* Make sure your hashcat brain server is protected with a good password, because you have to trust your clients
* I'll add a standalone hashcat brain seeding tool later which enables you to easily push all the words from an entire wordlist or a mask very fast. At this time you can use the `--hashcat-session` option to do so with hashcat itself
* You can use `--brain-server-whitelist` in order to force the clients to use a specific hashlist
* The protocol used is pretty simple and does not contain hashcat specific information, which should make it possible for other cracking tools to utilize the server, too

## Technical details on the hashcat brain client

The client calculates the hashcat brain session based on the hashlist entries, to efficiently let a high number of salts work for us. You can override the session calculated with `--brain-session`, which makes sense if you want to use a fast hash in order to "__seed__" the hashcat brain with already-tried wordlists or masks.

The use of `--remove` is forbidden, but this should not really be a problem, since the potfile will do the same for you. Make sure to remove `--potfile-disable` in case you use it.

If multiple clients use the same attack on the same hashcat brain (which is a clever idea), you end up with a distributed solution - without the need of an overlay for keyspace distribution. This is not the intended use of the hashcat brain and should not be used as it. I'll explain later.

Since each password candidate is creating a hash of 8 bytes, some serious network upstream traffic can be generated from your client. I'll explain later.

The use of xxHash as hash is not required; we can exchange it with whatever hash we want. However so far it's doing a great job.
The status view was updated to give you some real-time statistics about the network usage:

```
Speed.#1.........:        0 H/s (0.00ms) @ Accel:64 Loops:1 Thr:1024 Vec:1
Speed.#2.........:        0 H/s (0.00ms) @ Accel:64 Loops:1 Thr:1024 Vec:1
Speed.#3.........:        0 H/s (0.00ms) @ Accel:64 Loops:1 Thr:1024 Vec:1
Speed.#4.........:        0 H/s (0.00ms) @ Accel:64 Loops:1 Thr:1024 Vec:1
...
Brain.Link.#1....: RX: 0 B (0.00 Mbps), TX: 4.1 MB (1.22 Mbps), sending
Brain.Link.#2....: RX: 0 B (0.00 Mbps), TX: 4.7 MB (1.09 Mbps), sending
Brain.Link.#3....: RX: 0 B (0.00 Mbps), TX: 3.5 MB (0.88 Mbps), sending
Brain.Link.#4....: RX: 0 B (0.00 Mbps), TX: 4.1 MB (0.69 Mbps), sending
```

When the data is transferred, there's no cracking. You can see it's doing 0 H/s. But if you have a slow hash, or a fast hash with multiple salts, this time can be seen as minor overhead. The major time taken is still in the cracking phase. So if you have a fast hash, the more salts the better! As soon as hashcat is done with the network communication, it's starting to work as always:

```
Speed.#1.........:   869.1 MH/s (1.36ms) @ Accel:64 Loops:1 Thr:1024 Vec:1
Speed.#2.........:   870.8 MH/s (1.36ms) @ Accel:64 Loops:1 Thr:1024 Vec:1
Speed.#3.........:   876.2 MH/s (1.36ms) @ Accel:64 Loops:1 Thr:1024 Vec:1
Speed.#4.........:   872.6 MH/s (1.36ms) @ Accel:64 Loops:1 Thr:1024 Vec:1
...
Brain.Link.#1....: RX: 1.3 MB (0.00 Mbps), TX: 10.5 MB (0.00 Mbps), idle
Brain.Link.#2....: RX: 1.3 MB (0.00 Mbps), TX: 10.5 MB (0.00 Mbps), idle
Brain.Link.#3....: RX: 1.3 MB (0.00 Mbps), TX: 10.5 MB (0.00 Mbps), idle
Brain.Link.#4....: RX: 1.3 MB (0.00 Mbps), TX: 10.5 MB (0.00 Mbps), idle
```

## The brain and the bottlenecks

While working with Team Hashcat to test how the brain performs with large numbers of clients and over the Internet, I learned about some serious bottlenecks.

The most important insight was about the performance of lookups against the brain. That should be obvious solely from the huge amount of data that we're talking about here, but the brain does not just have to look up millions of candidates against millions of existing database entries - it must also insert them into the database after each commit and ensure the ordering stays intact otherwise it would break the binary tree. This simply takes time, even if the lookup process was already threaded. But the feature was so promising that I did not want to abandon development just because of the performance challenge.

But to start from the beginning, keep the following number in mind: 50kH/s

This was the speed that was the maximum performance of the hashcat brain after the first development alpha was finished. In other words, if the performance of your attack was faster than this speed, the hashcat brain becomes the bottleneck.

Now there's good and bad news about this:

* __Bad:__ This is the total number. Which means, the entire network of all GPUs participating as clients cannot create more than 50kH/s before the bottleneck effect kicks in.
* __Good:__ Salts come to the rescue. If you have a large salted hashlist - with, for example 300,000 SSHA1 hashes (as in the last Crack Me If You Can) - this means that the real maximum performance that the brain can handle jumps to 15 GH/s. (You can simply multiply the 50kH/s with the number of unique salts of your hashlist.)

Then there's another bottleneck: the network bandwidth required. For those of you who plan to use the brain inside a local network with 100Mbit, you can skip this section entirely. But for those who plan to use the brain in a large group, over VPN or in general over the Internet, keep in mind that a single GPU can create around 5Mbit/s of upstream before bandwidth becomes a bottleneck. That doesn't mean that a hashcat client will stop working - it will just reduce your theoretical maximum cracking performance.

Both of these lessons learned lead to an upgrade to the brain during development. (This means that everything that you've read up to this point is already outdated!) The bottlenecks still exist, but there's kind of a mitigation to them. To better understand what we mean when talking about how to mitigate the problem, we need new terminology in the hashcat brain universe - something we'll call brain client "features".

When running as a client, hashcat now has a new parameter called --brain-client-features. With this parameter, you can select from two features (so far) that the client has to offer:
Brain "Hashes" feature
Brain "Attacks" feature
The brain "hashes" feature is everything that we've explained from the beginning - the *low-level* function of the brain. The brain "attacks" feature is the *high-level* strategy which I added to mitigate the bottlenecks. By default, both "features" are active, and run in parallel. Depending on your use case, you can selectively enable or disable either one.

The brain "attack" feature should be explained in more detail in order to understand what it is doing. It is a high-level approach, or a compressed hint. Hashcat clients request this "hint" from the brain about a given attack as soon as the client is assigned a new work package from the local hashcat dispatcher. For example, if you have a system with 4 GPUs, the local hashcat dispatcher is responsible for distributing the workload across the local GPUs. What's new is that before a GPU starts actually working on the package, it asks the brain for a high level confirmation of whether or not to proceed. The process of how this work is basically the same as with the low-level architecture: the client "reserves" a package when the hashcat brain moves it to short-term memory - and once it is done, it will be moved to long-term memory.

The attack package itself is another 8-byte checksum - but that's more than enough to assign all feasible combinations of attacks a unique identifier. For example, hashcat takes options like the attack mode itself, rules with `-r` (but also `-j` and `-k` rules), masks, user-defined custom charset, Markov options, a checksum of the wordlists (if used) and so on. All of these options are combined in a repeatable way, and from that unique combination of options, a checksum is created that uniquely "fingerprints" all of the components of the attack.

When the clients connect to the hashcat brain, they send this attack checksum (along with the session ID) to the brain, so that the brain knows precisely which attack is running on a particular hashcat client. Now, if the local dispatcher creates a new package, the local start point and end point of this attack is sent to the brain so that the brain can track it. The client will automatically reject an entire package - for example, an entire wordlist, or an entire wordlist plus a specific list of rules - if the attack has some overlaps. This is done *before* the client sends any password candidate hashes to the brain.

This means that if a package is rejected:

* The client doesn't need to transfer the hashes (which mitigates the bandwidth bottleneck)
* The brain server doesn't need to compare it (which mitigates the lookup bottleneck)

If the attack package itself is not rejected, the hashes are still sent to the brain and compared.

The hashcat brain is kind of clever when it comes to the packages. It recognizes overlapping packages on a low level - in cases where only part of one package overlaps with another package. When this occurs, the brain only rejects the overlapping section of the package and informs the client about that. It is then up to the client to decide whether it wants to either launch the attack with a minimized package size, or to ask the local dispatcher for another (smaller) portion to fill the gap. Of course, this newly creates portion is also first sent to the brain, in case it can be rejected. The entire process is packed into a loop and it will repeat the process until the client decides that the package is big enough (and the default setting for accepting a package and to start executing is half of the original package size.)

Something I realized - after I had already finished with the implementation of the high-level feature - was that the new brain "attack" feature is a very strong feature for standalone use. By setting `--brain-client-features 2`, you tell the client to only use the attack feature. This completely eliminates all bottlenecks - the network bandwidth, but even more importantly, the lookup bottleneck. The drawback is that you lose cross-attack functionality.

If you think that this new feature is a nice way to get a native hashcat multi-system distribution ... you are wrong. The brain client still requires running in `-S` mode, which means that this is all about slow hashes or fast hashes with many salts. There's also no wordlist distribution, and most importantly, there's no distribution of cracked hashes across all network clients. So the brain "attack" feature is not meant to be an alternative to existing distribution solutions, but just as a mitigation for the bottlenecks (and it works exactly as such).

## Commandline Options

Most of the commands are self-explaining. I'm just adding them here to inform you which ones exist:

- `--brain-server` to start a hashcat brain server
- `--brain-client` to start a hashcat brain client, automatically activates --slow-candidates
- `--brain-host` and `--brain-port` to specify ip and port of brain server, both listening and connecting
- `--brain-session` to override automatically calculated brain session ID
- `--brain-session-whitelist` to allow only explicit written session ID on brain server
- `--brain-password` to specify the brain server authentication password
- `--brain-client-features` which allows enable and disable certain features of the hashcat brain
