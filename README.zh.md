# dsh-plugin-folder-trust

Windows 专用：**新增工作区后，先问一次「信任此文件夹吗？」**，点「信任文件夹」就地为该目录补齐 DSH `workspace-write` 沙箱所需的那一条 NTFS 权限，之后工作区里的受限 shell 才能写入，不会再每次都要在对话里提权。

## 为什么需要它

DSH 在 Windows 上把「工作区内修改」实现成：受限令牌 + 按工作区路径派生的 SID 写权限 ACE + Low 完整性标签，全部在一次 `SetNamedSecurityInfoW` 里落盘。这一次调用要求当前账户对工作区根目录同时有 **WRITE_DAC**（改权限）和 **WRITE_OWNER**（改属主/完整性标签）。缺任何一个，DSH 自己就补不上授权，于是每条受限命令在启动前就被拒绝（`SetNamedSecurityInfoW failed (Win32 5): grantWrite(...)`），用户只能切「完全权限」继续。

本插件把这一步变成一次点击：

1. 监听持久化工作区注册表（`ctx.workspaceRegistry.list()`），**插件启动之后新增**的工作区才参与判定；
2. 对新目录只读探测两个权利（真实令牌，不提权）；
3. 权利齐全 → 直接记住，不打扰；
4. 缺权利 → 浏览器弹出模态「信任此文件夹吗？」，两个选择：
   - **信任文件夹**：给你的账户补一条完全控制 ACE，再按 DSH 的算法把能力 SID 的 ACE 与 Low 标签铺进已有子树，校验后记住该路径；
   - **忽略**：只把该路径记进 `state.json` 的 `dismissed`，**不会再为这个文件夹弹窗**，也不改动任何权限。弹窗里明说了后续代价：在「工作区内修改」模式下 DSH 仍无法为它准备写权限，之后每次需要在其中写入时沙箱都会再次请求授权（或临时切到「完全权限」）。

## 输入框里的权限检查

DSH 的工作区行「…」菜单**没有插件扩展点**（rename/delete 是 dsh-client-ui-workspace 里写死的数组，只有*会话行*菜单是 slot），所以检查入口放在输入框右侧的控制行，紧挨着 pwsh7 那个 chip：

- **正常时不显示**：当前会话所属工作区的权限齐全，控制行里没有这个按钮；
- **异常时显示「工作区权限异常」**：外框写死为 20px 高、108px 宽（与 pwsh7 的 20px 控制行同高、同圆角），不依赖旁边有没有 pwsh7；
- 点开后**只列出当前工作区**的三组状态和「修复权限」，不再把其它工作区摊在一起。

当前工作区是这样认出来的：`conversation.input.right` 是 `session` 作用域的插槽，宿主会把 `sessionId` 和一组快照 hook 作为标准 props 交给组件（不需要 `inject`，重复注入反而会撞上标准 prop）。按顺序取第一个拿得到的目录：

1. `useSessions((s) => s.byId[sessionId]?.cwd)`——会话列表摘要里的工作区目录，DSH 自己的输入框也是这么读的（`useSession()` 返回的是快照，没有 `cwd`，别用它）；
2. `useWorkspaces(...)` 里 `sessionIds` 含该会话的那一行的 `path`；
3. 浏览器侧 `workspaces` 服务的快照（侧栏工作区树读的同一个 store），作为兜底；
4. 宿主报告行若带 `sessionIds`（宿主重载后才有），再按它认领一次。

全都拿不到时按钮保持隐藏，不猜别的工作区。判定用的 `issues` / `needsRepair` 由宿主算好放进报告行；宿主还没重载时，浏览器按 `permissions` 自己推同样的结论（`issuesOf()` 的兜底分支），所以只刷新页面也能完整工作。

## 设置页：所有工作区的权限

「设置 → 工作区权限」是同一份报告的完整体，列出**每个已注册工作区**：

- 账户能否改权限 / 改所有者（缺哪个就写哪个）；
- 沙箱写入授权是否已落在根目录；
- 一级子文件夹里有几个已继承授权（x/y）；
- 包含 %TEMP% 的工作区标记为不可用。

有问题的行带「修复权限」：补当前账户完全控制 → 把授权与 Low 标签按名字铺进已有子树 → 重新探测并刷新该行状态。修复只对已注册工作区生效。页面右上角「重新检测」会绕过 15 秒缓存重新探测。

两处入口共用 `lib/status.mjs` 的判定（`issues` / `needsRepair` 由宿主在报告行里算好），所以「什么算需要修复」不存在两份实现。

想撤销「忽略」：从 `state.json` 的 `dismissed` 里删掉该路径（重启后生效），再重新加一次工作区即可重新提示。

## 组成

| 文件 | 职责 |
|---|---|
| `index.js` | 宿主入口：注入 `webServer`，等 `workspaceRegistry` 就绪后启动轮询，注册路由 |
| `lib/service.mjs` | 工作区判定、待信任队列、`~/.dsh/folder-trust/state.json` 持久化、报告行（含 `issues` / `needsRepair` / `sessionIds`） |
| `lib/status.mjs` | 纯判定：路径归一化、问题码、是否需要修复、按路径找行 |
| `lib/acl.mjs` | 探测 WRITE_DAC/WRITE_OWNER；缺则补完全控制 ACE 并复读校验（Windows PowerShell 5.1 子进程，输出走临时文件、不占用管道） |
| `lib/routes.mjs` | `GET /folder-trust/state`、`POST /folder-trust/trust`、`POST /folder-trust/dismiss`、`GET /folder-trust/report`、`POST /folder-trust/repair`、`GET/POST /folder-trust/debug`；只接受待办路径或已注册工作区，浏览器无法让宿主改任意目录 |
| `client.js` | `shell.overlay` 的信任模态（2 秒轮询）、输入框的权限检查（15 秒轮询）、`settings.section` 的「工作区权限」页 |
| `test/` | ACL 探测/授权幂等性、工作区判定与拒绝持久化、判定规则 |

`POST /folder-trust/debug` 只接收浏览器上报的插槽 props 摘要（`data-slot` 诊断用），`GET` 返回它和轮询状态；两者都不改任何权限。

## 行为边界

- **子目录会被一起铺开**：DSH 用目录句柄写入授权和 Low 标签，句柄写入不触发继承，所以工作区根可用而"早就存在"的子目录不可用。插件按 DSH 的算法自己派生同一个 S-1-4 SID（sha256(规范化路径) 的两段 30 位），按名字重写根目录的 DACL/SACL，让 Windows 把 ACE 与标签递归铺到整棵已有子树，并在子目录上抽样校验；已信任的路径启动时也补做一次，结果记在 `state.json` 的 `propagated`。
- **不会提权**：用的是 DSH 自己的令牌。目录连 WRITE_DAC 都没有（例如属主是 SYSTEM、你只有读取或修改权限）时，插件会失败并提示改用「完全权限」或让管理员修一次。
- **工作区包含 `%TEMP%`**（例如直接拿 `C:\Users\<你>` 当工作区）时沙箱结构性不可用：信任弹窗只说明原因、不给「信任」，检查按钮与设置页把它标为不可用且不提供修复。
- 授权只落在工作区子树，不改文件内容、不改属主、不删任何 ACE；`state.json` 记录已信任/已拒绝/已铺开的路径。
- 只影响 Windows；其他平台该行不会被插入。

## 安装 / 卸载

profile 里把它加进 `dsh.profile.bundles` 与依赖，并在 `profiles/desktop/node_modules` 建指向本包的链接即可。卸载时删掉这两处（`package.json`、`bundles` 里的 `dsh-plugin-folder-trust`）并删除链接，刷新页面后插件不再加载。

改了宿主半侧（`index.js`、`lib/*.mjs`）后需要重启 DSH（或重新加载该插件）才生效；只改 `client.js` 时刷新页面即可。
