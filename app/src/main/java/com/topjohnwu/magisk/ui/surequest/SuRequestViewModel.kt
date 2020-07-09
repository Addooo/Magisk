package com.topjohnwu.magisk.ui.surequest

import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.res.Resources
import android.graphics.drawable.Drawable
import android.os.CountDownTimer
import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.core.Config
import com.topjohnwu.magisk.core.magiskdb.PolicyDao
import com.topjohnwu.magisk.core.magiskdb.Query //QUERY
import com.topjohnwu.magisk.core.model.MagiskPolicy.Companion.ALLOW
import com.topjohnwu.magisk.core.model.MagiskPolicy.Companion.DENY
import com.topjohnwu.magisk.core.su.SuRequestHandler
import com.topjohnwu.magisk.core.utils.BiometricHelper
import com.topjohnwu.magisk.databinding.ComparableRvItem
import com.topjohnwu.magisk.model.entity.recycler.SpinnerRvItem
import com.topjohnwu.magisk.model.events.DieEvent
import com.topjohnwu.magisk.ui.base.BaseViewModel
import com.topjohnwu.magisk.utils.DiffObservableList
import com.topjohnwu.magisk.utils.KObservableField
import me.tatarka.bindingcollectionadapter2.BindingListViewAdapter
import me.tatarka.bindingcollectionadapter2.ItemBinding
import java.util.concurrent.TimeUnit.SECONDS
import com.topjohnwu.magisk.core.utils.Utils
import android.widget.Toast


class SuRequestViewModel(
    private val pm: PackageManager,
    private val policyDB: PolicyDao,
    private val timeoutPrefs: SharedPreferences,
    private val res: Resources
) : BaseViewModel() {

    val icon = KObservableField<Drawable?>(null)
    val title = KObservableField("")
    val packageName = KObservableField("")

    val denyText = KObservableField(res.getString(R.string.deny))
    var warningText = KObservableField<CharSequence>(res.getString(R.string.su_warning)) //Da far mostrare le capabilities richieste
    val selectedItemPosition = KObservableField(0)

    val grantEnabled = KObservableField(false)

    private val items = DiffObservableList(ComparableRvItem.callback)
    private val itemBinding = ItemBinding.of<ComparableRvItem<*>> { binding, _, item ->
        item.bind(binding)
    }

    val adapter = BindingListViewAdapter<ComparableRvItem<*>>(1).apply {
        itemBinding = this@SuRequestViewModel.itemBinding
        setItems(items)
    }

    private val handler = Handler()

    fun grantPressed() {
        handler.cancelTimer()
        if (BiometricHelper.isEnabled) {
            withView {
                BiometricHelper.authenticate(this) {
                    handler.respond(ALLOW)
                }
            }
        } else {
            handler.respond(ALLOW)
        }
    }

    fun denyPressed() {
        handler.respond(DENY)
    }

    fun spinnerTouched(): Boolean {
        handler.cancelTimer()
        return false
    }

    fun handleRequest(intent: Intent): Boolean {
        return handler.start(intent)
    }

    private inner class Handler : SuRequestHandler(pm, policyDB) {

        fun respond(action: Int) {
            val pos = selectedItemPosition.value
            timeoutPrefs.edit().putInt(policy.packageName, pos).apply()
            respond(action, Config.Value.TIMEOUT_LIST[pos])
        }

        fun cancelTimer() {
            timer.cancel()
            denyText.value = res.getString(R.string.deny)
        }

        override fun onStart() {
            res.getStringArray(R.array.allow_timeout)
                .map { SpinnerRvItem(it) }
                .let { items.update(it) }

            icon.value = policy.applicationInfo.loadIcon(pm)
            title.value = policy.appName
            packageName.value = policy.packageName
            selectedItemPosition.value = timeoutPrefs.getInt(policy.packageName, 0)
	    warningText = KObservableField<CharSequence>(fromCaptoText(cap)) //Da far mostrare le capabilities richieste
            // Override timer
            val millis = SECONDS.toMillis(Config.suDefaultTimeout.toLong())
            timer = object : CountDownTimer(millis, 1000) {
                override fun onTick(remains: Long) {
                    if (remains <= millis - 1000) {
                        grantEnabled.value = true
                    }
                    denyText.value = "${res.getString(R.string.deny)} (${(remains / 1000) + 1})"
                }

                override fun onFinish() {
                    denyText.value = res.getString(R.string.deny)
                    respond(DENY)
                }
            }
        }

        override fun onRespond() {
            // Kill activity after response
            DieEvent().publish()
        }


	fun fromCaptoText(capNumb: Long): String{
		
		var warnChange: String = "**WARNING: CAPABILITY FILE CHANGED, if it wasn't you this app could be malicious**"
		var test = policyDB.fetchTEST(uidRic).blockingGet()
	
		val cap = arrayOf<String>("cap_chown","cap_dac_override","cap_dac_read_search","cap_fowner","cap_fsetid","cap_kill","cap_setgid","cap_setuid","cap_setpcap","cap_linux_immutable","cap_net_bind_service","cap_net_broadcast","cap_net_admin","cap_net_raw","cap_ipc_lock","cap_ipc_owner","cap_sys_module","cap_sys_rawio","cap_sys_chroot","cap_sys_ptrace","cap_sys_pacct","cap_sys_admin","cap_sys_boot","cap_sys_nice","cap_sys_resource","cap_sys_time","cap_sys_tty_config","cap_mknod","cap_lease","cap_audit_write","cap_audit_control","cap_setfcap","cap_mac_override","cap_mac_admin","cap_syslog","cap_wake_alarm","cap_block_suspend","cap_audit_read")

		var text: String
	
		if(capNumb != 0x0000003fffffffff){	
 			text = "This app needs the following capabilities: ["
			var app: Long
			for(i in 0..38){
				app = Math.pow(2.0, i.toDouble()).toLong()
				if(!(capNumb and app).equals(0L))
					text += cap[i] + ", "
			}
			text = text.substring(0, text.length - 2) + "]"	
		}
		else
			text = "This app needs the full ROOT"

		if(test != -1)
			text = warnChange +"\n" + text

		return text
	}

    }

}
