# 发布流程（Windows）

本包发布到 npm 需要人工过 2FA，其余步骤都已脚本化。

## 一次配好（只需第一次）

1. 登录（浏览器 + OTP）：

        npm.cmd login --auth-type=web
        npm.cmd whoami

2. 首次发布：

        npm.cmd publish --access public

3. 配置 trusted publisher（npm >= 11.17，会走网页 2FA）：

        npm.cmd trust github dsh-plugin-folder-trust --file publish.yml --repo drliuhuan/dsh-plugin-folder-trust --allow-publish -y
        npm.cmd trust list dsh-plugin-folder-trust

> 不要在 package.json 里写 publishConfig.provenance: true：本机发布时 provider 是 null，
> npm 会直接以 EUSAGE Automatic provenance generation not supported for provider: null 失败。
> provenance 只在 CI 里由 --provenance 生成。

## 以后每次发版

        npm.cmd version patch     # 或 minor / major
        git push --follow-tags
        gh release create vX.Y.Z --title "vX.Y.Z" --notes "..."

publish workflow 在 Release 发布时用 OIDC 自动发布并附带 provenance，本机不再需要 OTP。

## 常用脚本

        npm.cmd run release:check     # 测试 + 打包清单预演
        npm.cmd run release:publish   # 首次本机发布
        npm.cmd run release:trust     # 配置 trusted publisher
