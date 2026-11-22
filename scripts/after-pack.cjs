// Flip Electron fuses on the packaged binary: disable RunAsNode, NODE_OPTIONS, inspect, and file:// privileges.
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses')
const path = require('node:path')

module.exports = async function afterPack(context) {
  const { electronPlatformName, appOutDir } = context
  const exe =
    electronPlatformName === 'win32'
      ? 'NEXUS Terminal.exe'
      : electronPlatformName === 'darwin'
        ? `${context.packager.appInfo.productFilename}.app`
        : context.packager.executableName

  await flipFuses(path.join(appOutDir, exe), {
    version: FuseVersion.V1,
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: false,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: false
  })
}
