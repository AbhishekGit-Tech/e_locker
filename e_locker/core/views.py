from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.contrib import messages
import secrets
from django.contrib.auth import logout
from django.core.mail import send_mail
from django.conf import settings
# Create your views here.

def landing(request):
    if request.user.is_authenticated:
        return redirect('home')
    return render(request, 'core/landing.html')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        step = request.POST.get('step')

        # — STEP 1: Registration form submitted
        if step == 'form':
            u = request.POST['username'].strip()
            e = request.POST['email'].strip()
            p = request.POST['password']
            c = request.POST['confirm_password']

            # Validations
            if p != c:
                messages.error(request, "Passwords don’t match.")
                return render(request,'core/register.html',{'step':'form'})
            if User.objects.filter(username=u).exists():
                messages.error(request, "Username taken.")
                return render(request,'core/register.html',{'step':'form'})
            if User.objects.filter(email=e).exists():
                messages.error(request, "Email already used.")
                return render(request,'core/register.html',{'step':'form'})

            # Generate & email OTP
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

        # — STEP 2: OTP entry
        if step == 'otp':
            entered = request.POST.get('otp_input','').strip()
            real    = request.session.get('reg_otp')
            if entered == real:
                # Create user
                user = User.objects.create_user(
                    username=request.session['reg_username'],
                    email=   request.session['reg_email'],
                    password=request.session['reg_password']
                )
                user.save()
                # Clean up session except nothing else
                for k in ['reg_username','reg_email','reg_password','reg_otp']:
                    request.session.pop(k, None)
                messages.success(request, "Registered! Now log in below.")
                return redirect('login_simple')

            messages.error(request, "Invalid OTP.")
            return render(request, 'core/register.html', {'step': 'otp'})

    # GET or fallback
    return render(request, 'core/register.html', {'step': 'form'})


def login_simple_view(request):
    # Simple login immediately after registration (no OTP)
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        u = request.POST['username']
        p = request.POST['password']
        user = authenticate(request, username=u, password=p)
        if user:
            login(request, user)
            return redirect('home')
        messages.error(request, "Invalid credentials.")
    return render(request, 'core/login_simple.html')


def login_view(request):
    # OTP-based login for returning users
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        step = request.POST.get('step')

        # STEP 1: username/password submitted → send OTP
        if step == 'form':
            u = request.POST['username']
            p = request.POST['password']
            user = authenticate(request, username=u, password=p)
            if not user:
                messages.error(request, "Invalid username/password.")
                return render(request,'core/login.html',{'step':'form'})

            otp = f"{secrets.randbelow(9000)+1000:04d}"
            request.session['login_username'] = u
            request.session['login_password'] = p
            request.session['login_otp']      = otp

            send_mail(
                subject="e-Locker Login OTP",
                message=f"Your login code is {otp}",
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                fail_silently=False,
            )
            return render(request, 'core/login.html', {'step':'otp'})

        # STEP 2: OTP entry → final authentication
        if step == 'otp':
            entered = request.POST.get('otp_input','').strip()
            real    = request.session.get('login_otp')
            if entered == real:
                u = request.session.pop('login_username')
                p = request.session.pop('login_password')
                request.session.pop('login_otp')
                user = authenticate(request, username=u, password=p)
                if user:
                    login(request, user)
                    return redirect('home')
            messages.error(request, "Invalid OTP.")
            return render(request, 'core/login.html', {'step':'otp'})

    return render(request, 'core/login.html', {'step':'form'})


@login_required
def home(request):
    return render(request, 'core/home.html')


def logout_view(request):
    logout(request)
    return redirect('landing')