"""
Extended user models for VULNRIX accounts.
"""
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
import secrets
import hashlib


class UserProfile(models.Model):
    """
    Extended user profile with API key support and preferences.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # API Authentication
    api_key_hash = models.CharField(max_length=64, blank=True, null=True, db_index=True)
    api_key_created_at = models.DateTimeField(null=True, blank=True)
    api_requests_count = models.IntegerField(default=0)
    api_requests_limit = models.IntegerField(default=1000)  # Monthly limit
    
    # Preferences
    dark_mode = models.BooleanField(default=True)
    email_notifications = models.BooleanField(default=True)
    slack_webhook = models.URLField(blank=True, null=True)
    
    # Linked Accounts
    github_username = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    
    # Monitoring
    monitoring_enabled = models.BooleanField(default=False)
    monitoring_interval_hours = models.IntegerField(default=24)
    monitoring_targets_json = models.TextField(blank=True, null=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
    
    def __str__(self):
        return f"Profile: {self.user.username}"
    
    def generate_api_key(self) -> str:
        """
        Generate a new API key and store its hash.
        Returns the plain text key (only shown once).
        """
        # Generate key
        raw_key = f"vx_{secrets.token_urlsafe(32)}"
        
        # Store hash
        self.api_key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        from django.utils import timezone
        self.api_key_created_at = timezone.now()
        self.save()
        
        return raw_key
    
    def revoke_api_key(self):
        """Revoke the current API key."""
        self.api_key_hash = None
        self.api_key_created_at = None
        self.save()
    
    def increment_api_usage(self):
        """Increment API request counter."""
        self.api_requests_count += 1
        self.save(update_fields=['api_requests_count'])
    
    def is_api_limit_exceeded(self) -> bool:
        """Check if user has exceeded their API limit."""
        return self.api_requests_count >= self.api_requests_limit


class Organization(models.Model):
    """
    Organization for team features.
    """
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    plan = models.CharField(max_length=20, choices=[
        ('free', 'Free'),
        ('pro', 'Pro'),
        ('team', 'Team'),
        ('enterprise', 'Enterprise'),
    ], default='free')
    
    # Limits
    member_limit = models.IntegerField(default=1)
    scan_limit = models.IntegerField(default=50)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Organization'
        verbose_name_plural = 'Organizations'
    
    def __str__(self):
        return self.name


class Membership(models.Model):
    """
    User membership in an organization.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='memberships')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(max_length=20, choices=[
        ('owner', 'Owner'),
        ('admin', 'Admin'),
        ('member', 'Member'),
        ('viewer', 'Viewer'),
    ], default='member')
    
    joined_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('user', 'organization')
        verbose_name = 'Membership'
        verbose_name_plural = 'Memberships'
    
    def __str__(self):
        return f"{self.user.username} - {self.organization.name} ({self.role})"


# Signal to create profile when user is created
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()
