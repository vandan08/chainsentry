/** Shield mark — inherits currentColor for the ring, accent for the check. */
export function Logo() {
  return (
    <svg className="logo" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 4.5 5.5v6c0 4.5 3.1 8.4 7.5 10 4.4-1.6 7.5-5.5 7.5-10v-6L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="m8.5 12 2.4 2.4 4.6-4.8"
        stroke="var(--series-1)"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
