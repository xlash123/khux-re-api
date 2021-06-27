# What is a UUID
A UUID is a random string that is generated per device. This UUID is linked with your account login. However, if you sign in to you account on a new device, that device's UUID is from then on the new linked UUID of your device.

The UUID is the only thing needed to log into your account, so keep it a secret.

# How can I obtain my UUID?
You can obtain your UUID by capturing the data packets between your device and the KHUx servers. This can be done easily on Android 7 and below. If you don't have Android 7 or below, then you can easily do this method using Bluestacks.

1. Install [Bluestacks](https://www.bluestacks.com/) on your computer.
2. Open up **Bluestacks** when it finishes installing.
3. Download and install [KHUx](https://apkpure.com/kingdom-hearts-u%CF%87-dark-road/com.square_enix.android_googleplay.khuxww/download?from=details)
4. Download and install [Packet Capture](https://apkpure.com/packet-capture/app.greyshirts.sslcapture/download?from=details) apk
5. Open the **Packet Capture** app in Bluestacks
6. When prompted to, click **Install Certificate**
7. Click the Play button with a little 1 next to it in the top right
8. Select **KHUx** in the list
9. Go to the home screen and open **KHUx**
10. Click **KHUx Start**
11. Click **Agree**
12. Click the **sign-in option** that you've used to link your account
13. After logging in successfully, let the game go back to the **title screen**.
14. Close **KHUx**
15. In the **Packet Capture** app, select the first item in the list
16. Select the 8th item from the bottom
17. You should see something like `{"UUID":"<data here>","deviceType":2 ...`
18. Highlight the data after "UUID" in between the quotation marks and click copy.

Congrats! You now have your UUID! Keep this a secret from others as it is the only data needed to log into an account.

You can now backup your data using the info on the [Readme](/README.md#Backup)