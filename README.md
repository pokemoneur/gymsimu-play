# GymSimu Beta – Cergyius Gym

[Play GymSimu in your browser](https://pokemoneur.github.io/gymsimu-play/).

Each account starts with three empty save slots. Choose **Create Account** or **Sign In** to keep progress private to your account and sync it across devices. The first sign-in for the owner account can import saves already stored by this game in the same browser. Other accounts start blank. Use the in-game export option for an additional backup.

The browser client uses a Supabase publishable key with row-level security. Passwords are handled by Supabase Auth and are never stored in the game database. Database setup scripts: [`202611160001_gym_users_and_saves.sql`](202611160001_gym_users_and_saves.sql) and [`202611160002_developer_access.sql`](202611160002_developer_access.sql).

This game is separate from Remind-er.
