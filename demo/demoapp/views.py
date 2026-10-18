from django.shortcuts import render


def home(request):
    return render(request, "demoapp/page.html", {
        "title": "Home",
        "blurb": "An ordinary page. The gate sits in front of every view in "
                 "this project, so if you can read this you were not flagged "
                 "as automated, or you already passed a passkey check.",
    })


def reports(request):
    return render(request, "demoapp/page.html", {
        "title": "Reports",
        "blurb": "Another ordinary view. Nothing gate-specific in the code.",
    })
