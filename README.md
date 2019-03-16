# CredentialStorage
Semi-secure library for storing user credentials in memory.

In a project that required frequent reuse of user authentication credentials, a solution was required that would allow 
the credentials to be stored in memory so that the user would not have to re-enter them, while at the same time making
it difficult for other processes to simply read the credentials from memory.

This code could easily be decompiled, and malicious software could be built to circumvent this protection. As such, an
alternate solution such as the use of API keys should be used in high security scenarios. This code is a sample of a
method for handling credential storage, and should not be considered highly secure. This is simply a demo, and provided
as-is. The author of this code assumes no responsibility for issues resulting from the use, or misuse, of this code.