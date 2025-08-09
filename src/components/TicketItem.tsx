import type { Ticket } from "@/generated/prisma";
import Link from "next/link";
import { getPriorityClass } from "@/utils/ui";

type TicketItemProps = {
  ticket: Ticket;
};

const TicketItem = ({ ticket }: TicketItemProps) => {
  const isClosed = ticket.status.toLowerCase() === "closed";

  return (
    <div
      className={`flex justify-between items-center bg-white rounded-lg shadow border border-gray-200 p-6 ${
        isClosed ? "opacity-50 cursor-not-allowed" : ""
      }`}
    >
      {/* Left Side */}
      <h2 className="text-xl font-semibold text-blue-600">{ticket.subject}</h2>

      {/* right side */}
      <div className="text-right space-y-2">
        <div className="text-sm text-gray-500">
          Priority:{" "}
          <span className={getPriorityClass(ticket.priority)}>
            {ticket.priority}
          </span>
        </div>
        <div className="text-sm text-gray-500">
          Status:{" "}
          <span
            className={`font-bold ${
              isClosed ? "text-red-600" : "text-green-600"
            }`}
          >
            {ticket.status}
          </span>
        </div>
        <Link
          href={`/tickets/${ticket.id}`}
          className={`inline-block mt-2 text-sm px-3 py-1 rounded transition text-center ${
            ticket.status === "closed"
              ? "bg-gray-400 text-gray-700 cursor-not-allowed pointer-events-none"
              : "bg-blue-600 text-white hover:bg-blue-700 "
          }`}
        >
          View Ticket
        </Link>
      </div>
    </div>
  );
};

export default TicketItem;
