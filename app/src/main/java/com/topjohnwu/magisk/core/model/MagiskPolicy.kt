package com.topjohnwu.magisk.core.model

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.topjohnwu.magisk.core.model.MagiskPolicy.Companion.INTERACTIVE
import com.topjohnwu.magisk.extensions.getLabel

import com.topjohnwu.magisk.core.utils.Utils
import android.widget.Toast

data class MagiskPolicy(
    var uid: Int,
    val packageName: String,
    val appName: String,
    var policy: Int = INTERACTIVE,
    var until: Long = -1L,
    var capab: Long = 0x3fffffffff, //TEST
    val logging: Boolean = true,
    val notification: Boolean = true,
    val applicationInfo: ApplicationInfo
) {

    companion object {
        const val INTERACTIVE = 0
        const val DENY = 1
        const val ALLOW = 2
    }

}

fun MagiskPolicy.toMap() = mapOf(
    "uid" to uid,
    "package_name" to packageName,
    "policy" to policy,
    "until" to until,
    "logging" to logging,
    "notification" to notification,
    "capab" to capab //TEST
)

@Throws(PackageManager.NameNotFoundException::class)
fun Map<String, String>.toPolicy(pm: PackageManager): MagiskPolicy {
    val uid = get("uid")?.toIntOrNull() ?: -1
    val packageName = get("package_name").orEmpty()
    val info = pm.getApplicationInfo(packageName, PackageManager.GET_UNINSTALLED_PACKAGES)

    if (info.uid != uid)
        throw PackageManager.NameNotFoundException()
    //Utils.toast("Ciao qua ci sono", Toast.LENGTH_SHORT)
    return MagiskPolicy(
        uid = uid,
        packageName = packageName,
        policy = get("policy")?.toIntOrNull() ?: INTERACTIVE,
        until = get("until")?.toLongOrNull() ?: -1L,
        logging = get("logging")?.toIntOrNull() != 0,
        capab = get("capab")?.toLongOrNull() ?: 0x3fffffffff, //TEST
        notification = get("notification")?.toIntOrNull() != 0,
        applicationInfo = info,
        appName = info.getLabel(pm)
    )
}

@Throws(PackageManager.NameNotFoundException::class)
fun Int.toPolicy(pm: PackageManager, policy: Int = INTERACTIVE): MagiskPolicy {
    val pkg = pm.getPackagesForUid(this)?.firstOrNull()
        ?: throw PackageManager.NameNotFoundException()
    val info = pm.getApplicationInfo(pkg, PackageManager.GET_UNINSTALLED_PACKAGES)
    return MagiskPolicy(
        uid = info.uid,
        packageName = pkg,
        policy = policy,
        applicationInfo = info,
//	capab = info.capab,
        appName = info.getLabel(pm)
    )
}
