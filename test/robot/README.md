
# Robot framework testing foor the registry

The following simple keywords are available:

- `Stock Stackql Exec Inline Equals Both Streams`.
- `Stock Stackql Exec Inline Contains Both Streams`.

Working examples are present, and you can add to them:

- For live tests, add to [`stackql/live/live.robot`](/test/robot/stackql/live/live.robot).  Authentication credentials must be supplied in the environment for any query under test.
- For moocked tests, add to [`stackql/mocked/adhoc.robot`](/test/robot/stackql/mocked/adhoc.robot).  Mocking capability must be present for any query under test.

Additionally, more complex keywords are available and more complex scenarios are supported.  Examples of such will be added on a needs basis, for corner cases.
