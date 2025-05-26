from django.db import models

# Create your models here.
from django.contrib.auth.models import User

class EncryptedFile(models.Model):
    owner      = models.ForeignKey(User, on_delete=models.CASCADE)
    name       = models.CharField(max_length=255)
    upload_ts  = models.DateTimeField(auto_now_add=True)
    nonce      = models.BinaryField()
    tag        = models.BinaryField()
    ciphertext = models.BinaryField()

    def __str__(self):
        return f"{self.name} ({self.owner.username})"
