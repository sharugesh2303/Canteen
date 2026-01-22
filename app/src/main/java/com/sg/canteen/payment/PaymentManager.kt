package com.sg.canteen.payment

import android.app.Activity
import com.razorpay.Checkout
import org.json.JSONObject

object PaymentManager {

    /* ================= CALLBACK HOLDERS ================= */
    private var successCallback: ((String?) -> Unit)? = null
    private var failureCallback: (() -> Unit)? = null

    /* ================= START PAYMENT ================= */
    fun startPayment(
        activity: Activity,
        amount: Int,
        onSuccess: (String?) -> Unit,
        onFailure: () -> Unit = {}
    ) {

        // Save callbacks so MainActivity can trigger them
        successCallback = onSuccess
        failureCallback = onFailure

        val checkout = Checkout()

        // ⚠️ Use TEST key only for development
        checkout.setKeyID("rzp_test_RWFHMvcRDEJN3E")

        val options = JSONObject().apply {
            put("name", "Canteen Order")
            put("description", "Food & Stationery")
            put("currency", "INR")

            // Razorpay expects amount in paise
            put("amount", amount * 100)
        }

        checkout.open(activity, options)
    }

    /* ================= PAYMENT SUCCESS ================= */
    fun notifySuccess(paymentId: String?) {
        successCallback?.invoke(paymentId)
        clearCallbacks()
    }

    /* ================= PAYMENT FAILURE ================= */
    fun notifyFailure() {
        failureCallback?.invoke()
        clearCallbacks()
    }

    /* ================= CLEANUP ================= */
    private fun clearCallbacks() {
        successCallback = null
        failureCallback = null
    }
}
