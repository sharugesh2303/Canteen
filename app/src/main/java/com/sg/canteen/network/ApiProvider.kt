package com.sg.canteen.network

object ApiProvider {
    val api: ApiService =
        ApiClient.retrofit.create(ApiService::class.java)
}
