<?php
/**
 * Réglages du formulaire de contact.
 * Ce fichier n'est pas accessible depuis le web (voir api/.htaccess).
 */
return [
    // Destinataire(s) des demandes
    'to' => ['info@proteckassistance.fr'],

    // Expéditeur technique : doit être une adresse du domaine qui héberge le site
    // (sinon les e-mails risquent de finir en spam — SPF/DKIM).
    'from_email' => 'no-reply@proteckinformatique.fr',
    'from_name' => 'Site Proteck',

    // Adresse de retour d'enveloppe (option -f de sendmail). Laisser vide si l'hébergeur le refuse.
    'envelope_sender' => 'no-reply@proteckinformatique.fr',

    // Anti-spam
    'min_seconds' => 3,       // délai minimal entre l'affichage de la page et l'envoi
    'max_per_hour' => 5,      // envois maximum par heure et par adresse IP
    'salt' => 'XXK9d6IaNAgZIJncvFDlu6m8mIW3MDuM', // sert à rendre les empreintes d'IP non réversibles

    // Dossier de travail (limitation anti-spam). Doit être accessible en écriture par PHP.
    'data_dir' => __DIR__ . '/data',
];
