"""The second-factor step — correct in both halves of the lab, on purpose.

This file is neither the vulnerable view nor the secure one. It is the step that
turns an authenticated session into a *verified* one, and it is written the right
way in both worlds, because the vulnerability this lab teaches is not here.

That is itself a finding, and it changed the shape of this lab while I was
building it. The plan called for a second pair: an unthrottled verify endpoint
beside a throttled one, so a reader could watch a six-digit code get brute-forced.
You cannot write that pair honestly against ``django-otp``, because
``TOTPDevice.verify_token()`` throttles itself:

    verify_allowed, _ = self.verify_is_allowed()
    if not verify_allowed:
        return False
    ...
    if not verified:
        self.throttle_increment(commit=True)

The backoff starts at the **first** failure and doubles — 1, 2, 4, 8, 16 seconds —
and the counter lives in the device row, so it survives a restart and, verified
through django_otp.verify_token() below, holds across workers. Turning it off takes
a deliberate, documented setting, ``OTP_TOTP_THROTTLE_FACTOR = 0``, and a lab
whose bug is "someone set the throttle to zero" teaches configuration review, not
MFA, so this lab does not contain one. ``tests.py`` asserts the library's behaviour instead, which means a
future release that weakens it turns this repo red rather than quietly making the
post wrong.
"""

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django_otp import login as otp_login, verify_token
from django_otp.plugins.otp_totp.models import TOTPDevice


@csrf_exempt
@require_POST
def verify(request):
    if not request.user.is_authenticated:
        return HttpResponse("log in first\n", status=401)

    device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
    if device is None:
        return HttpResponse("no confirmed device\n", status=400)

    # django_otp.verify_token() reloads the device with select_for_update() inside a
    # transaction, so the device's throttle holds against concurrent attempts too.
    code = request.POST.get("code", "")
    if verify_token(request.user, device.persistent_id, code) is None:
        return HttpResponse("bad code\n", status=401)
    # THE line that makes is_verified() true for this session. Without it the
    # code was checked and then forgotten, and @otp_required would still refuse.
    otp_login(request, device)
    return HttpResponse("verified\n")
