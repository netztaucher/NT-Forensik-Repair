/*
   NT-Forensik — Sammel-Regeldatei
   ------------------------------------------------------------------
   yara nimmt genau EINE Regeldatei entgegen. Diese Datei bindet alle
   Regelsätze per include ein, damit der Scan in Abschnitt 7.11
   unverändert bleiben kann.

   Neue Regelsätze hier eintragen. Bedingung für jede eingebundene Datei:
   sie darf keine externen Variablen ausser "filename" verlangen — der
   Scan übergibt nur diese eine, und eine fehlende Variable lässt yara
   die gesamte Sammlung mit einem Übersetzungsfehler abweisen.
*/

include "gsocket-backdoors.yar"
include "joomla-malware.yar"
