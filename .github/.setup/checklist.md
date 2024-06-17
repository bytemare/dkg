# GitHub repository basic setup

This is a checklist of a basic setup for your GitHub repo.

## Files
- [ ] Replace all occurrences of dkg with the lowercase repo name
- [ ] Replace all occurrences of dkg with the uppercase repo name
- [ ] Add a `LICENSE` file with the year(s) and name
- [ ] Add a `README.md` file at the root
  - [ ] State the purpose of the project
  - [ ] State how people can get, install, and use the project
  - [ ] Link to documentation
  - [ ] What versions are supported? What do they mean? Very often you would go with SemVer here
  - [ ] Refer where one can find how to contribute (e.g. link to the `CONTRIBUTING.md` file in `.github`)
  - [ ] Refer to the License
- [ ] `CITATION.cff`
- [ ] Use a relevant `.gitignore` file
- [ ] Setup the `.github` folder
  - [ ] `SECURITY.md`
  - [ ] `CONTRIBUTING.md`
  - [ ] `CODE_OF_CONDUCT.md`
  - [ ] `CODEOWNERS`
  - [ ] `ISSUE_TEMPLATE`
  - [ ] `PULL_REQUEST_TEMPLATE`
  - Makefile for neat automation
  - [ ] workflows
    - [ ] Repo Security Monitoring (e.g. scorecards)
    - [ ] Dependency Security Monitoring (e.g. Snyk, dependabot, renovate)
    - [ ] Code Security Analysis (e.g. CodeQL, SonarCloud, Coverity)
    - [ ] Linting (e.g. licence-header, golangci-lint, ShellCheck, YAML file linter)
    - [ ] Unit tests
    - [ ] Coverage (e.g. Codecov, Coveralls)

## Repo settings

- topics, find the right hashtags!

- [ ] General
  - [ ] Require contributors to sign off on web-based commits
  - [ ] Allow merge commits
  - [ ] Allow squash merging
  - [ ] Always suggest updating pull request branches
  - [ ] Allow auto-merge
  - [ ] Automatically delete head branches
- [ ] Branch Protection
  - [ ] Require a pull request before merging
    - [ ] Dismiss stale pull request approvals when new commits are pushed
    - [ ] Require review from Code Owners
  - [ ] Require status checks to pass before merging
    - [ ] Require branches to be up to date before merging
    - e.g. of Status checks: DCO, Snyk, Tests from CI, coverage, code linting and analysis
  - [ ] Require conversation resolution before merging
  - [ ] Require signed commits
  - [ ] Do not allow bypassing the above settings
- [ ] Declare GitHub Workflow tokens as read only
- [ ] Tokens
  - [ ] SONAR_TOKEN
  - [ ] SCORECARD_READ_TOKEN
  - [ ] CODECOV_TOKEN
- [ ] Open new projects on
  - [ ] Sonar Cloud https://sonarcloud.io
  - [ ] OpenSSF https://www.bestpractices.dev
    - Note the project ID
    - Fill out project descriptions, and replace {{.ID}} in README with that ID

## Git setup

- GPG sign
- run .github/setup/auto-sign-off.sh

- auto sign-off: https://stackoverflow.com/a/46536244/6310488
> Save the following as .git/hooks/prepare-commit-msg or .git/hooks/commit-msg (see here for the differences: https://git-scm.com/docs/githooks)
> ``` sh
> #!/bin/sh
> 
> NAME=$(git config user.name)
> EMAIL=$(git config user.email)
> 
> if [ -z "$NAME" ]; then
>   echo "empty git config user.name"
>   exit 1
> fi
> 
> if [ -z "$EMAIL" ]; then
>   echo "empty git config user.email"
>   exit 1
> fi
> 
> git interpret-trailers --if-exists doNothing --trailer \
>   "Signed-off-by: $NAME <$EMAIL>" \
>   --in-place "$1"
> ```

## MISC

- Project description, find the right topics for better referencing
- Fuzzing
- Cryptographically sign releases
