"""The escalation target, shared by both twins.

Returns the flag only to a profile whose `role == "staff"`. Nothing here is
vulnerable — it is an ordinary authorisation gate. It exists so that *capturing
the flag is the escalation*: a member who has flipped their own `role` to `staff`
through the vulnerable form can now read it; a member who tried the same through
the secure form still gets a 403.
"""
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.utils.html import escape

from .models import Flag, Profile


@login_required
def staff_area(request):
    role = Profile.objects.get(user=request.user).role
    if role != "staff":
        return HttpResponseForbidden(
            f"403 — staff only (you are '{escape(role)}')\n"
        )
    flag = (Flag.objects.first() or Flag(value="")).value
    return HttpResponse(f"<h1>Staff area</h1><p>{escape(flag)}</p>")
