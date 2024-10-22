export interface StatusMessage {
  message: string;
  type: "success" | "danger";
}

export const StatusMessageView = ({
  statusMessageList,
  setStatusMessageList,
}: {
  statusMessageList: StatusMessage[];
  setStatusMessageList: React.Dispatch<React.SetStateAction<StatusMessage[]>>;
}) => (
  <>
    {statusMessageList.map((statusMessage, index) => (
      <div
        key={index}
        className={`alert alert-${statusMessage.type} alert-dismissible fade show`}
        role="alert"
      >
        {statusMessage.message}
        <button
          type="button"
          className="btn-close"
          data-bs-dismiss="alert"
          aria-label="Close"
          onClick={() => {
            setStatusMessageList(
              statusMessageList.filter((_, i) => i !== index)
            );
          }}
        ></button>
      </div>
    ))}
  </>
);
