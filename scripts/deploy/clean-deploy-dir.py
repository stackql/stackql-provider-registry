import os, shutil

print("getting REG_WEBSITE_DIR env var...")
website_dir = os.getenv('REG_WEBSITE_DIR')

print("removing all objects except %s..." % (website_dir))
objects = os.listdir('.')
for obj in objects:
    if os.path.isdir(obj):
        if obj != website_dir:
            shutil.rmtree(obj)
    else:
        os.remove(obj)

print("copying objects from %s to root of working dir..." % (website_dir))
objects = os.listdir(website_dir)
for obj in objects:
    if os.path.isdir("%s/%s" % (website_dir, obj)):
        shutil.copytree("%s/%s" % (website_dir, obj), obj)
    else:
        shutil.copy("%s/%s" % (website_dir, obj), obj)

print("removing %s..." % (website_dir))
shutil.rmtree(website_dir)
