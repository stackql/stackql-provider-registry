
## Pull Requests

Please fork our repository and then raise a Pull Request (PR) against our `dev` branch.  Please add a fulsome description in the Pull Request comment.  We will attend to it and work with you as soon as possible.  

Once the PR is approved, we will sign any changed files, package for distribution and squash / merge the combined change set into the `dev` branch.  Once merged into `dev`, changes will instantly be available to `stackql` applications configured to integrate the `dev` registry.  After an additional period of monitoring from the team, it will be promoted to our main / production branch.  This equates to publication for default configured instances of `stackql`.

## Provider Document Requirements

Provider documents are signed and published by CI after merge, so the pipeline enforces the layout below and rejects anything else:

- documents live at `providers/src/<provider>/v00.00.00000/provider.yaml` and `providers/src/<provider>/v00.00.00000/services/<service>.yaml`, nothing else is permitted under the version directory
- provider directory names and service file names must start with a letter, digit or `_` and contain only letters, digits, `.`, `_` and `-`
- every entry must be a regular file or directory; symbolic links are not permitted anywhere under `providers/src`
