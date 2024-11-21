# Releasing KubeMarine

If you want to make a new KubeMarine release, you need to do following:
1. On the `main` branch, update KubeMarine version and create tag (replace `X.X.X` with actual version):
    ```
    python3 -m pip install bumpver
    python3 -m bumpver update --set-version=X.X.X
    ```
2. Wait for [GitHub Actions](https://github.com/Netcracker/KubeMarine/actions) completion and verify newly create pre-release on [GitHub Release page](https://github.com/Netcracker/KubeMarine/releases). Following artifacts are essential for each release:
    * KubeMarine binaries for different OS. They could be found in release assets.
    * KubeMarine python distribution package. It could be found in release assets.
    * [KubeMarine image](https://github.com/Netcracker/KubeMarine/pkgs/container/kubemarine).
    * [Kubemarine documentation](https://github.com/Netcracker/KubeMarine/tree/main/documentation).
3. Once you have verified that KubeMarine artifacts are OK, change your release from `pre-release` to `latest release` on [GitHub Release page](https://github.com/Netcracker/KubeMarine/releases). This will publish KubeMarine distribution package to PyPI.
