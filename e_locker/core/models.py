from django.db import models

from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
# Create your models here.

class EncryptedFile(models.Model):
    owner      = models.ForeignKey(User, on_delete=models.CASCADE)
    name       = models.CharField(max_length=255)
    upload_ts  = models.DateTimeField(auto_now_add=True)
    nonce      = models.BinaryField()
    tag        = models.BinaryField()
    ciphertext = models.BinaryField()

    def __str__(self):
        return f"{self.name} ({self.owner.username})"
    
class UserProfile(models.Model):
    user     = models.OneToOneField(User, on_delete=models.CASCADE)
    last_key = models.CharField(max_length=64, blank=True, default='')

    def __str__(self):
        return f"Profile for {self.user.username}"
    


@receiver(post_save, sender=User)
def create_or_update_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
    else:
        instance.userprofile.save()
