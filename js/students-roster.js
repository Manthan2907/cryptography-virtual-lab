/**
 * Virtual Cryptography Laboratory - Class Roster & Roll Number Lookup
 * Official TE-COMPS Student Roster from CSS Virtual Lab Allocation
 */
const STUDENTS_ROSTER = (() => {
  // Master official roster
  const ROSTER = {
    "10705": "Ahamed Wafiq",
    "10706": "Rohit Ahir",
    "10707": "Sai Balkawade",
    "10708": "Slora Bar",
    "10709": "Arya Chavan",
    "10710": "Tanush Chavan",
    "10711": "Jace Jaison",
    "10712": "Aarna Chopdekar",
    "10713": "Swar",
    "10714": "Ulric Collaco",
    "10715": "Asher",
    "10716": "Jadern Crasto",
    "10717": "Nicole Dabre",
    "10718": "Larissa Dabreo",
    "10719": "Aaron Deniz",
    "10720": "Shreyas Divekar",
    "10721": "Ruth Dmello",
    "10722": "Alciya Dodti",
    "10723": "Cajetan Dsouza",
    "10724": "Wendell Dsouza",
    "10725": "Aaron Emmaty",
    "10726": "Wayne Falco",
    "10727": "Rishal Fernandes",
    "10728": "Soah Fernandes",
    "10729": "Nemi Gada",
    "10730": "Bliss Gonsalves",
    "10731": "Sherwin Gonsalves",
    "10732": "Kinjal Goyal",
    "10733": "Sanika Gunjal",
    "10734": "Daksh Gurav",
    "10736": "Shivam Jha",
    "10737": "Maria Joanna",
    "10739": "Abhishek Roy Jose",
    "10740": "Vedant Kanekar",
    "10742": "Rahul Kewat",
    "10743": "Crisann Lobo",
    "10744": "Ojas Manjrekar",
    "10745": "Stewin Mathias",
    "10746": "Reeven Menezes",
    "10747": "Joel Wilson",
    "10748": "Manthan Pagaria",
    "10749": "Omkar Patil",
    "10750": "Chris Pereira",
    "10751": "Lebron Pereira",
    "10752": "Ephraim T Philip",
    "10753": "Shaaunak Pitale",
    "10754": "Arnav Potale",
    "10755": "Dev Dinesh Saroj",
    "10756": "Aarya Sawant",
    "10757": "Rahul Senapati",
    "10758": "Vihan Shah",
    "10759": "Niranjan Shanbhag",
    "10760": "Diva Sharma",
    "10761": "Daksh Shetty",
    "10762": "Disha Shetty",
    "10763": "Shwet Shigwan",
    "10764": "Priyanka Thapa",
    "10765": "Sven Tuscano",
    "10766": "Anaay Vakharkar",
    "10767": "Jeremiah Yangal",
    "10895": "Sakshi",
    "10920": "Aisha Fernandes",
    "10921": "Eva Gonsalves",
    "10922": "Kamesh Nerpagar",
    "10923": "Aditya Pisal",
    "10924": "Sameer",
    "10925": "Royson Rodrigues"
  };

  // Build lookup index with 2-digit and 3-digit shorthand
  const LOOKUP = {};
  for (const [roll, name] of Object.entries(ROSTER)) {
    LOOKUP[roll] = { fullRoll: roll, name: name };

    // Suffix aliases (e.g. 10701 -> 01, 10705 -> 05 and 5)
    if (roll.startsWith("107")) {
      const suffix = roll.slice(3); // "48", "05"
      LOOKUP[suffix] = { fullRoll: roll, name: name };
      if (suffix.startsWith("0")) {
        LOOKUP[suffix.slice(1)] = { fullRoll: roll, name: name }; // "5"
      }
    } else if (roll.startsWith("109")) {
      const suffix = roll.slice(3); // "20"
      LOOKUP[suffix] = { fullRoll: roll, name: name };
      LOOKUP["9" + suffix] = { fullRoll: roll, name: name };
    } else if (roll.startsWith("108")) {
      const suffix = roll.slice(3);
      LOOKUP[suffix] = { fullRoll: roll, name: name };
      LOOKUP["8" + suffix] = { fullRoll: roll, name: name };
    }
  }

  function findStudent(query) {
    if (!query) return null;
    const clean = String(query).trim().replace(/^#/, '');
    return LOOKUP[clean] || null;
  }

  return {
    ROSTER,
    LOOKUP,
    findStudent
  };
})();

if (typeof window !== 'undefined') {
  window.STUDENTS_ROSTER = STUDENTS_ROSTER;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = STUDENTS_ROSTER;
}
