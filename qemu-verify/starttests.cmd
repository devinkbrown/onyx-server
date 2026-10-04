@echo off
for %%d in (C D E F G H) do if exist %%d:\autorun.cmd call %%d:\autorun.cmd
