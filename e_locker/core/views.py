from django.shortcuts       import render, redirect
from django.contrib.auth    import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib         import messages
from django.core.mail       import send_mail
from django.conf            import settings
import secrets

def landing(request):
    # Prevent a freshly-created superuser from auto-landing:
    if request.user.is_authenticated:
        if request.user.is_superuser:
            logout(request)
            return render(request, 'core/landing.html')
        return redirect('home')
    return render(request, 'core/landing.html')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        step = request.POST.get('step')

        # STEP 1: Registration form
        if step == 'form':
            u = request.POST['username'].strip()
            e = request.POST['email'].strip()
            p = request.POST['password']
            c = request.POST['confirm_password']

            if p != c:
                messages.error(request, "Passwords don’t match.")
                return render(request,'core/register.html',{'step':'form'})
            if User.objects.filter(username=u).exists():
                messages.error(request, "Username taken.")
                return render(request,'core/register.html',{'step':'form'})
            if User.objects.filter(email=e).exists():
                messages.error(request, "Email already used.")
                return render(request,'core/register.html',{'step':'form'})

            otp = f"{secrets.randbelow(900000)+100000:06d}"
            request.session['reg_username'] = u
            request.session['reg_email']    = e
            request.session['reg_password'] = p
            request.session['reg_otp']      = otp

            send_mail(
                subject="e-Locker Registration OTP",
                message=f"Your registration code is {otp}",
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[e],
                fail_silently=False,
            )
            return render(request, 'core/register.html', {'step': 'otp'})

        # STEP 2: OTP verification
        if step == 'otp':
            entered = request.POST.get('otp_input','').strip()
            real    = request.session.get('reg_otp')
            if entered == real:
                user = User.objects.create_user(
                    username=request.session['reg_username'],
                    email=   request.session['reg_email'],
                    password=request.session['reg_password']
                )
                user.save()
                # clean up reg data only
                for k in ('reg_username','reg_email','reg_password','reg_otp'):
                    request.session.pop(k, None)
                messages.success(request, "Registered! Now log in below.")
                return redirect('login_simple')

            messages.error(request, "Invalid OTP.")
            return render(request, 'core/register.html', {'step': 'otp'})

    # GET or fallback
    return render(request, 'core/register.html', {'step': 'form'})


def resolve_user(identifier):
    """Return User object matching username or email, or None."""
    if "@" in identifier:
        return User.objects.filter(email__iexact=identifier).first()
    else:
        return User.objects.filter(username__iexact=identifier).first()


def login_simple_view(request):
    if request.method == 'POST':
        ident = request.POST['identifier'].strip()
        pwd   = request.POST['password']
        user_obj = resolve_user(ident)
        if not user_obj:
            messages.error(request, "No account with that username/email.")
        else:
            user = authenticate(request, username=user_obj.username, password=pwd)
            if user:
                login(request, user)
                return redirect('home')
            messages.error(request, "Invalid credentials.")
    return render(request, 'core/login_simple.html')


def login_otp_view(request):
    if request.method == 'POST':
        step = request.POST.get('step')

        # STEP 1: send OTP
        if step == 'form':
            ident = request.POST['identifier'].strip()
            user_obj = resolve_user(ident)
            if not user_obj:
                messages.error(request, "No account with that username/email.")
                return render(request, 'core/login.html', {'step':'form'})

            otp = f"{secrets.randbelow(9000)+1000:04d}"
            request.session['login_identifier'] = ident
            request.session['login_otp']        = otp

            send_mail(
                "e-Locker Login OTP",
                f"Your code is {otp}",
                settings.EMAIL_HOST_USER,
                [user_obj.email],
                fail_silently=False,
            )
            return render(request, 'core/login.html', {'step':'verify'})

        # STEP 2: verify password+OTP
        if step == 'verify':
            combo = request.POST.get('password','')
            real  = request.session.get('login_otp')
            ident = request.session.get('login_identifier')

            entered_otp = combo[-4:] if len(combo)>4 else ''
            entered_pw  = combo[:-4]

            user_obj = resolve_user(ident)
            if entered_otp == real and user_obj:
                user = authenticate(request, username=user_obj.username, password=entered_pw)
                if user:
                    # clean up
                    request.session.pop('login_otp', None)
                    request.session.pop('login_identifier', None)
                    login(request, user)
                    return redirect('home')

            messages.error(request, "Invalid password+OTP combination.")
            return render(request, 'core/login.html', {'step':'verify'})

    return render(request, 'core/login.html', {'step':'form'})


@login_required
def home(request):
    # Each user sees only their page.
    return render(request, 'core/home.html', {
        'username': request.user.username,
        'email':    request.user.email,
        # add other user-specific data here
    })


def logout_view(request):
    logout(request)
    return redirect('landing')
