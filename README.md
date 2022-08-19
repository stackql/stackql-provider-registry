
# StackQL Provider Registry

A repository of `provider` interface documents supporting [stackql](https://stackql.io/) ([github](https://github.com/stackql/stackql)). 

## Contributing

Please see [.github/CONTRIBUTING.md](/.github/CONTRIBUTING.md).

## Current Providers

Please see [our distribution root](/providers/dist) for an up-to-date list.

Some notable inclusions:

- github
- google
- netlify
- okta

## Signing and verification

### Philosophy and design

See [docs/signing-and-verification.md](/docs/signing-and-verification.md).


### Working with the command line tool

See [docs/command-line-tool.md](/docs/command-line-tool.md).

## Distribution

- **Initial Naive Implementation** with laggy distribution through GitHub / [Statically](https://statically.io/) as per [this walkthrough](https://blog.mergify.com/how-to-serve-static-files-from-github/).
- **Strategic Implementation** to follow, possibly using an authentication-enabled CDN such as [Bunny](https://bunny.net/solutions/software-distribution).  At this time, we will not commit to a specific product or set of client requirements.  We shall consult with community and industry before adding features over and above the naive.

## Provide archiving and compression

Simple tar gzip, eg:

```
cd providers/src/googleapis.com

tar -czf v0.1.0.tgz v0.1.0
```

To decompress, simply `tar -xzf v0.1.1.tgz`.
